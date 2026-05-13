import { Inject, Injectable, Logger } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { TypedEvents } from '../shared/typed-events';
import { totp as authenticator } from '../shared/totp.util';
import { MFA_CONFIG, type MfaConfig } from '../config/slices';
import { MfaChallengeRepository } from './repositories/mfa-challenge.repository';
import { MfaTokenRepository } from './repositories/mfa-token.repository';
import { UserSecretsRepository } from './repositories/user-secrets.repository';
import { aesGcmDecrypt } from '../shared/aes-gcm.util';
import { MFA_FAILED, MFA_RATE_LIMITED, MFA_SECRET_DECRYPT_FAILED } from '../policy/policy-events';
import { MfaErrorRecorder } from './mfa-error-recorder.util';
import type { MfaTokenClaims } from './interfaces/mfa-token-claims.interface';

export type MfaCreateResult =
  | { ok: true; challengeId: string; expiresAt: number }
  | { ok: false; reason: 'rate_limited' | 'internal' };

export type MfaVerifyResult =
  | { ok: true; token: string; expiresAt: number }
  | { ok: false; reason: 'expired_challenge' | 'invalid_code' | 'unknown_user' | 'internal' };

export type MfaValidateResult =
  | { ok: true; claims: MfaTokenClaims }
  | {
      ok: false;
      reason:
        | 'signature'
        | 'expired'
        | 'fingerprint_mismatch'
        | 'revoked'
        | 'unknown_jti'
        | 'wrong_type'
        /**
         * BL-01 (phase 14): infrastructure failure (DB unavailable, etc.).
         * Distinguishes a transient repo error from a real signature failure.
         * Callers MUST treat this as fail-closed (reject the promotion) but
         * MUST NOT emit MFA_FAILED for it — operators investigating an MFA
         * outage previously saw a flood of fake "signature" events.
         */
        | 'internal';
    };

/**
 * Phase C (260513-mar) — MfaChallenger: the challenge-half of the former
 * MfaService god-class. Owns challenge lifecycle, TOTP verification, MFA
 * JWT minting/validation. Consumed by GatewayMiddleware (hot path) and
 * MfaController.
 *
 * NEVER throws — all methods return discriminated unions.
 * MfaController maps ok:false results to HTTP responses (controller-owned
 * mapping idiom).
 *
 * Security notes:
 * - Fingerprint = SHA-256(userId|deviceId|ip) captured ONLY at verifyTotp time (D-05, Pitfall 5).
 * - MFA JWT signed with MFA_JWT_SECRET — separate from JWT_SECRET (D-09).
 * - typ:'mfa' claim prevents cross-service token confusion (D-10).
 * - Every validation failure emits MFA_FAILED via EventEmitter2 (D-12).
 * - Rate-limit denials emit MFA_RATE_LIMITED, NOT MFA_FAILED (D-18, Pitfall 8).
 */
@Injectable()
export class MfaChallenger {
  private readonly jwtSecretBytes: Uint8Array;
  private readonly encryptionKey: string;
  private readonly challengeTtlMs: number;
  private readonly tokenTtlMs: number;
  private readonly rateLimitMax: number;
  private readonly rateLimitWindowMs: number;

  constructor(
    @Inject(MFA_CONFIG) cfg: MfaConfig,
    private readonly challengeRepo: MfaChallengeRepository,
    private readonly tokenRepo: MfaTokenRepository,
    private readonly secretsRepo: UserSecretsRepository,
    private readonly events: TypedEvents,
    private readonly errorRecorder: MfaErrorRecorder,
  ) {
    this.jwtSecretBytes = new TextEncoder().encode(cfg.jwtSecret);
    this.encryptionKey = cfg.totpEncryptionKey;
    this.challengeTtlMs = cfg.challengeTtlMs;
    this.tokenTtlMs = cfg.tokenTtlMs;
    this.rateLimitMax = cfg.rateLimitMax;
    this.rateLimitWindowMs = cfg.rateLimitWindowMs;
  }

  /**
   * Creates an MFA challenge for userId. Rate-limited per D-17.
   * Returns { ok: true, challengeId, expiresAt } or { ok: false, reason }.
   */
  async createChallenge(userId: string, ip: string, ja4h?: string): Promise<MfaCreateResult> {
    try {
      // WR-05 (phase 14): atomic conditional insert closes the count + insert
      // TOCTOU window. The previous two-query pattern allowed N concurrent
      // requests for the same userId to each see count < max and all insert,
      // blowing past MFA_RATE_LIMIT_MAX, under-reporting MFA_RATE_LIMITED, and
      // amplifying the TOTP-attempt window. The atomic helper inserts iff the
      // count predicate is still satisfied at write time.
      const challengeId = randomUUID();
      const expiresAt = new Date(Date.now() + this.challengeTtlMs);
      const inserted = await this.challengeRepo.insertChallengeIfUnderLimit(
        challengeId,
        userId,
        expiresAt,
        this.rateLimitWindowMs,
        this.rateLimitMax,
      );
      if (!inserted) {
        // D-18: rate-limit denial emits MFA_RATE_LIMITED, not MFA_FAILED
        this.events.emit(MFA_RATE_LIMITED, {
          type: MFA_RATE_LIMITED,
          ip,
          userId,
          ja4h,
          ts: Date.now(),
        });
        return { ok: false, reason: 'rate_limited' };
      }
      return { ok: true, challengeId, expiresAt: expiresAt.getTime() };
    } catch (err) {
      this.errorRecorder.record(MfaChallenger.name, 'createChallenge', userId, err);
      return { ok: false, reason: 'internal' };
    }
  }

  /**
   * Verifies TOTP code against stored encrypted secret.
   * On success: mints MFA JWT bound to ip + deviceId fingerprint, stores in mfa_tokens.
   * On failure: emits MFA_FAILED and returns { ok: false, reason }.
   *
   * Fingerprint is captured HERE (verify time), not at initiate time (Pitfall 5, D-05).
   */
  async verifyTotp(
    challengeId: string,
    totpCode: string,
    userId: string,
    ip: string,
    deviceId: string,
    ja4h?: string,
  ): Promise<MfaVerifyResult> {
    const emitFail = (reason: string): void => {
      this.events.emit(MFA_FAILED, {
        type: MFA_FAILED,
        ip,
        userId,
        deviceId,
        ja4h,
        reason,
        ts: Date.now(),
      });
    };

    try {
      // 1. Challenge existence + expiry check
      const challenge = await this.challengeRepo.getChallenge(challengeId);
      if (!challenge || challenge.expiresAt.getTime() < Date.now()) {
        emitFail('expired_challenge');
        return { ok: false, reason: 'expired_challenge' };
      }

      // 2. Load + decrypt TOTP secret
      const encryptedSecret = await this.secretsRepo.getEncryptedSecret(userId);
      if (!encryptedSecret) {
        emitFail('unknown_user');
        return { ok: false, reason: 'unknown_user' };
      }
      const plainSecret = aesGcmDecrypt(encryptedSecret, this.encryptionKey);
      if (!plainSecret) {
        // WR-02 (phase 14): the response stays 'unknown_user' to preserve
        // enumeration resistance ("never reveal key state") — but the
        // internal observability MUST distinguish a corrupted / key-rotated
        // secret store from a genuinely missing row. Without this dashboards
        // could not alert on a spike of decrypt failures from a botched
        // MFA_TOTP_ENCRYPTION_KEY rotation.
        new Logger(MfaChallenger.name).warn('TOTP secret decrypt failed', { userId });
        this.events.emit(MFA_SECRET_DECRYPT_FAILED, {
          userId,
          ts: Date.now(),
        });
        emitFail('unknown_user');
        return { ok: false, reason: 'unknown_user' };
      }

      // 3. TOTP verification — otplib v12-adapter (synchronous, constant-time compare, Pitfall 1)
      const isValid = authenticator.verify({ token: totpCode, secret: plainSecret });
      if (!isValid) {
        emitFail('invalid_code');
        return { ok: false, reason: 'invalid_code' };
      }

      // 4. Fingerprint = SHA-256(userId|deviceId|ip) — captured at verify time (D-05, Pitfall 5)
      const fpHash = createHash('sha256')
        .update(`${userId}|${deviceId}|${ip}`, 'utf8')
        .digest('hex');

      // 5. Mint MFA JWT (D-10): { sub, jti, deviceId, fpHash, typ:'mfa', iat, exp }
      const jti = randomUUID();
      const expiresAtMs = Date.now() + this.tokenTtlMs;
      const expiresAtSec = Math.floor(expiresAtMs / 1000);
      const token = await new SignJWT({
        sub: userId,
        jti,
        deviceId,
        fpHash,
        typ: 'mfa',
      })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime(expiresAtSec)
        .sign(this.jwtSecretBytes);

      // 6. Persist token row for jti revocation check (D-08)
      await this.tokenRepo.insertMfaToken(jti, userId, fpHash, new Date(expiresAtMs));

      return { ok: true, token, expiresAt: expiresAtMs };
    } catch (err) {
      // WR-03 (phase 14): log + emit infra signal alongside the existing
      // MFA_FAILED { reason: 'internal' } so dashboards see the underlying
      // infra failure (the MFA_FAILED is for the threat ladder; mfa.infra_error
      // is for ops observability).
      this.errorRecorder.record(MfaChallenger.name, 'verifyTotp', userId, err);
      emitFail('internal');
      return { ok: false, reason: 'internal' };
    }
  }

  /**
   * Validates an MFA JWT from X-MFA-Token header.
   * Checks: signature → typ:'mfa' → jti in mfa_tokens (not expired/revoked) → fingerprint match.
   * Emits MFA_FAILED on any failure (D-12).
   * Called by GatewayMiddleware (step 9b — MFA promotion) on every request carrying X-MFA-Token.
   */
  async validateMfaToken(
    token: string,
    userId: string,
    deviceId: string,
    ip: string,
    ja4h?: string,
  ): Promise<MfaValidateResult> {
    const emitFail = (reason: string, jti?: string): void => {
      this.events.emit(MFA_FAILED, {
        type: MFA_FAILED,
        ip,
        userId,
        deviceId,
        ja4h,
        jti,
        reason,
        ts: Date.now(),
      });
    };

    try {
      // 1. Signature verification + basic claim extraction
      let payload: MfaTokenClaims;
      try {
        const { payload: p } = await jwtVerify(token, this.jwtSecretBytes, {
          algorithms: ['HS256'],
        });
        payload = p as unknown as MfaTokenClaims;
      } catch {
        emitFail('signature');
        return { ok: false, reason: 'signature' };
      }

      // 2. typ check — must be 'mfa' (D-10, prevents main JWT being used here)
      if (payload.typ !== 'mfa') {
        emitFail('wrong_type', payload.jti);
        return { ok: false, reason: 'wrong_type' };
      }

      // 3. WR-01 (phase 14): single atomic SELECT returns row + computed
      // revoked/expired flags. The prior two-query pattern (getMfaTokenStatus
      // followed by getMfaToken) opened a TOCTOU window where a concurrent
      // admin revoke between the two SELECTs would let a now-revoked token
      // pass through and validate. The atomic helper closes that window.
      const row = await this.tokenRepo.getMfaTokenWithStatus(payload.jti);
      if (row === null) {
        emitFail('unknown_jti', payload.jti);
        return { ok: false, reason: 'unknown_jti' };
      }
      if (row.isRevoked) {
        emitFail('revoked', payload.jti);
        return { ok: false, reason: 'revoked' };
      }
      if (row.isExpired) {
        // jose already caught this via JWTExpired above; defensive DB check
        emitFail('expired', payload.jti);
        return { ok: false, reason: 'expired' };
      }

      // 4. Fingerprint re-computation from current request context (D-06)
      const currentFp = createHash('sha256')
        .update(`${userId}|${deviceId}|${ip}`, 'utf8')
        .digest('hex');
      if (currentFp !== row.fingerprintHash) {
        emitFail('fingerprint_mismatch', payload.jti);
        return { ok: false, reason: 'fingerprint_mismatch' };
      }

      return { ok: true, claims: payload };
    } catch (err) {
      // BL-01 (phase 14): infra failures (DB / repo errors) used to land here
      // and be reported as 'signature' both to the caller AND to the MFA_FAILED
      // event bus — misleading incident triage and spuriously promoting threat
      // level via ThreatEscalationService.onMfaFailed. Route to the dedicated
      // 'internal' branch: fail-closed but NOT a security signal. The inner
      // try around jwtVerify already isolates true signature failures.
      // WR-03: log + emit mfa.infra_error via the shared MfaErrorRecorder
      // helper so dashboards see every MFA infra blip.
      this.errorRecorder.record(MfaChallenger.name, 'validateMfaToken', userId, err);
      return { ok: false, reason: 'internal' };
    }
  }
}
