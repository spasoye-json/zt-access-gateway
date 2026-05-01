import { Injectable } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { authenticator } from '@otplib/v12-adapter';
import { AppConfigService } from '../config/config.service';
import { MfaChallengeRepository } from './repositories/mfa-challenge.repository';
import { MfaTokenRepository } from './repositories/mfa-token.repository';
import { UserSecretsRepository } from './repositories/user-secrets.repository';
import { aesGcmDecrypt } from '../shared/aes-gcm.util';
import { MFA_FAILED, MFA_RATE_LIMITED } from '../policy/policy-events';
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
        | 'wrong_type';
    };

/**
 * Phase 7 — MfaService: challenge lifecycle, TOTP verification, MFA JWT minting/validation.
 *
 * NEVER throws — all methods return discriminated unions.
 * MfaController maps ok:false results to HTTP responses (same pattern as HashcashGuard).
 *
 * Security notes:
 * - Fingerprint = SHA-256(userId|deviceId|ip) captured ONLY at verifyTotp time (D-05, Pitfall 5).
 * - MFA JWT signed with MFA_JWT_SECRET — separate from JWT_SECRET (D-09).
 * - typ:'mfa' claim prevents cross-service token confusion (D-10).
 * - Every validation failure emits MFA_FAILED via EventEmitter2 (D-12).
 * - Rate-limit denials emit MFA_RATE_LIMITED, NOT MFA_FAILED (D-18, Pitfall 8).
 */
@Injectable()
export class MfaService {
  private readonly jwtSecretBytes: Uint8Array;
  private readonly encryptionKey: string;
  private readonly challengeTtlMs: number;
  private readonly tokenTtlMs: number;
  private readonly rateLimitMax: number;
  private readonly rateLimitWindowMs: number;

  constructor(
    cfg: AppConfigService,
    private readonly challengeRepo: MfaChallengeRepository,
    private readonly tokenRepo: MfaTokenRepository,
    private readonly secretsRepo: UserSecretsRepository,
    private readonly events: EventEmitter2,
  ) {
    this.jwtSecretBytes = new TextEncoder().encode(cfg.mfaJwtSecret);
    this.encryptionKey = cfg.mfaTotpEncryptionKey;
    this.challengeTtlMs = cfg.mfaChallengeTtlMs;
    this.tokenTtlMs = cfg.mfaTokenTtlMs;
    this.rateLimitMax = cfg.mfaRateLimitMax;
    this.rateLimitWindowMs = cfg.mfaRateLimitWindowMs;
  }

  /**
   * Creates an MFA challenge for userId. Rate-limited per D-17.
   * Returns { ok: true, challengeId, expiresAt } or { ok: false, reason }.
   */
  async createChallenge(
    userId: string,
    ip: string,
    ja4h?: string,
  ): Promise<MfaCreateResult> {
    try {
      const count = await this.challengeRepo.countRecentChallenges(userId, this.rateLimitWindowMs);
      if (count >= this.rateLimitMax) {
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

      const challengeId = randomUUID();
      const expiresAt = new Date(Date.now() + this.challengeTtlMs);
      await this.challengeRepo.insertChallenge(challengeId, userId, expiresAt);
      return { ok: true, challengeId, expiresAt: expiresAt.getTime() };
    } catch {
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
        // Decryption failure — treat as missing secret (never reveal key state)
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
      } as Record<string, unknown>)
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime(expiresAtSec)
        .sign(this.jwtSecretBytes);

      // 6. Persist token row for jti revocation check (D-08)
      await this.tokenRepo.insertMfaToken(jti, userId, fpHash, new Date(expiresAtMs));

      return { ok: true, token, expiresAt: expiresAtMs };
    } catch {
      emitFail('internal');
      return { ok: false, reason: 'internal' };
    }
  }

  /**
   * Validates an MFA JWT from X-MFA-Token header.
   * Checks: signature → typ:'mfa' → jti in mfa_tokens (not expired/revoked) → fingerprint match.
   * Emits MFA_FAILED on any failure (D-12).
   * Called by MfaGuard.canActivate() on every request carrying X-MFA-Token.
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

      // 3. Two-query jti lookup: distinguish unknown_jti from revoked (Fix-2 blocker).
      // Single getMfaToken() returns null for both cases — use a targeted SELECT instead.
      const jtiRow = await this.tokenRepo.getMfaTokenStatus(payload.jti);
      // jtiRow === null  → row doesn't exist at all → unknown_jti
      // jtiRow.isRevoked → row exists but revoked_at is set → revoked
      // jtiRow.isExpired → row exists but DB-side expired (redundant with jose exp check)
      if (jtiRow === null) {
        emitFail('unknown_jti', payload.jti);
        return { ok: false, reason: 'unknown_jti' };
      }
      if (jtiRow.isRevoked) {
        emitFail('revoked', payload.jti);
        return { ok: false, reason: 'revoked' };
      }
      if (jtiRow.isExpired) {
        // jose already caught this via JWTExpired above; defensive DB check
        emitFail('expired', payload.jti);
        return { ok: false, reason: 'expired' };
      }
      // Fetch the full row for fingerprint comparison
      const row = await this.tokenRepo.getMfaToken(payload.jti);
      if (!row) {
        // Race condition: row expired between status check and full fetch
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
    } catch {
      emitFail('signature');
      return { ok: false, reason: 'signature' };
    }
  }
}
