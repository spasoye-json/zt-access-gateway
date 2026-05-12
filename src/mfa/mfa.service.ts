import { Injectable, Logger } from '@nestjs/common';
import { createHash, randomUUID } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { totp as authenticator } from '../shared/totp.util';
import { AppConfigService } from '../config/config.service';
import { MfaChallengeRepository } from './repositories/mfa-challenge.repository';
import { MfaTokenRepository } from './repositories/mfa-token.repository';
import { UserSecretsRepository } from './repositories/user-secrets.repository';
import { aesGcmDecrypt, aesGcmEncrypt } from '../shared/aes-gcm.util';
import { MFA_ENROLLMENT_CONFIRMED, MFA_ENROLLMENT_RESET, MFA_FAILED, MFA_RATE_LIMITED } from '../policy/policy-events';
import { PendingEnrollmentStore } from './enrollment.store';
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
         * outage previously saw a flood of fake \"signature\" events.
         */
        | 'internal';
    };

// Phase 11 — Enrollment result types (D-10)
export type MfaEnrollResult =
  | { ok: true; enrollmentId: string; otpauthUri: string }
  | { ok: false; reason: 'already_enrolled' | 'internal' };

export type MfaConfirmResult =
  | { ok: true }
  | { ok: false; reason: 'expired_enrollment' | 'invalid_totp' | 'user_mismatch' | 'internal' };

export type MfaDeleteEnrollmentResult =
  | { ok: true; deleted: boolean }
  | { ok: false; reason: 'internal' };

/**
 * Phase 7 — MfaService: challenge lifecycle, TOTP verification, MFA JWT minting/validation.
 *
 * NEVER throws — all methods return discriminated unions.
 * MfaController maps ok:false results to HTTP responses (controller-owned mapping idiom).
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
  private readonly logger = new Logger(MfaService.name);
  /**
   * BL-02 (phase 14): cap on failed confirmEnrollment TOTP attempts per
   * pending-id. After exhaustion the pending entry is dropped and
   * MFA_RATE_LIMITED is emitted so ThreatEscalationService.onMfaRateLimited
   * observes the brute-force attempt.
   */
  static readonly ENROLL_MAX_ATTEMPTS = 5;
  private readonly jwtSecretBytes: Uint8Array;
  private readonly encryptionKey: string;
  private readonly challengeTtlMs: number;
  private readonly tokenTtlMs: number;
  private readonly rateLimitMax: number;
  private readonly rateLimitWindowMs: number;
  private readonly issuerName: string;

  constructor(
    cfg: AppConfigService,
    private readonly challengeRepo: MfaChallengeRepository,
    private readonly tokenRepo: MfaTokenRepository,
    private readonly secretsRepo: UserSecretsRepository,
    private readonly events: EventEmitter2,
    private readonly pendingStore: PendingEnrollmentStore,
  ) {
    this.jwtSecretBytes = new TextEncoder().encode(cfg.mfaJwtSecret);
    this.encryptionKey = cfg.mfaTotpEncryptionKey;
    this.challengeTtlMs = cfg.mfaChallengeTtlMs;
    this.tokenTtlMs = cfg.mfaTokenTtlMs;
    this.rateLimitMax = cfg.mfaRateLimitMax;
    this.rateLimitWindowMs = cfg.mfaRateLimitWindowMs;
    this.issuerName = cfg.mfaIssuerName;
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
    } catch (err) {
      // BL-01 (phase 14): infra failures (DB / repo errors) used to land here
      // and be reported as 'signature' both to the caller AND to the MFA_FAILED
      // event bus — misleading incident triage and spuriously promoting threat
      // level via ThreatEscalationService.onMfaFailed. Route to the dedicated
      // 'internal' branch: fail-closed but NOT a security signal. The inner
      // try around jwtVerify already isolates true signature failures.
      this.logger.error('MFA validation infra failure', err as Error);
      this.events.emit('mfa.infra_error', {
        userId,
        op: 'validateMfaToken',
        ts: Date.now(),
      });
      return { ok: false, reason: 'internal' };
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Phase 11 — Enrollment (D-01..D-10)
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Phase 11 — Generate a TOTP secret + otpauth URI for a non-enrolled user (D-01).
   *
   * Two-step flow: this method DOES NOT persist the secret. It stores a pending
   * entry in PendingEnrollmentStore (10-min TTL) keyed by a fresh UUIDv4 so the
   * client can complete a TOTP round-trip before commit. confirmEnrollment writes
   * to user_secrets only on a valid code (Pitfall 1).
   *
   * Returns 'already_enrolled' when user_secrets row exists (D-06 → 409 in controller).
   * Falls back to userId when userEmail absent (Pitfall 3).
   * Builds URI manually to comply with D-03 (Pitfall 4 — keyuri omits SHA1/6/30).
   */
  async createEnrollment(userId: string, userEmail?: string): Promise<MfaEnrollResult> {
    try {
      // D-06: block if already enrolled (confirmed) or pending enrollment exists
      if (this.pendingStore.hasPendingForUser(userId)) {
        return { ok: false, reason: 'already_enrolled' };
      }
      const existing = await this.secretsRepo.getEncryptedSecret(userId);
      if (existing) return { ok: false, reason: 'already_enrolled' };

      // D-03: generate base32 secret + manual otpauth URI (algorithm/digits/period explicit)
      const secret = authenticator.generateSecret();
      const label = userEmail ?? userId;
      const issuer = this.issuerName;
      const otpauthUri =
        `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(label)}` +
        `?secret=${secret}&issuer=${encodeURIComponent(issuer)}` +
        `&algorithm=SHA1&digits=6&period=30`;

      // D-02: stash pending entry; secret never leaves memory until confirm
      const enrollmentId = randomUUID();
      this.pendingStore.set(enrollmentId, { userId, secret });

      return { ok: true, enrollmentId, otpauthUri };
    } catch {
      return { ok: false, reason: 'internal' };
    }
  }

  /**
   * Phase 11 — Validate the TOTP code against the pending secret and commit (D-04).
   *
   * Failure modes (none throw):
   *   - expired_enrollment: pending entry missing or TTL expired
   *   - user_mismatch (T-11-01): caller userId doesn't match the pending entry's userId
   *   - invalid_totp: code didn't verify; pending entry is NOT deleted (retry within TTL)
   *
   * Success: AES-256-GCM-encrypts the secret, upserts user_secrets, deletes the pending
   * entry (Pitfall 1).
   */
  async confirmEnrollment(
    enrollmentId: string,
    totpCode: string,
    userId: string,
  ): Promise<MfaConfirmResult> {
    try {
      const pending = this.pendingStore.get(enrollmentId);
      if (!pending) return { ok: false, reason: 'expired_enrollment' };

      // T-11-01: enrollment must be confirmed by the same user who started it
      if (pending.userId !== userId) {
        return { ok: false, reason: 'user_mismatch' };
      }

      // D-04: same verify call as Phase 7 verifyTotp (window ±1, 30s period)
      const isValid = authenticator.verify({ token: totpCode, secret: pending.secret });
      if (!isValid) {
        // BL-02 (phase 14): emit MFA_FAILED so threat escalation observes the
        // failure, and bound retries per pending-id. Previously a stolen /
        // guessed enrollmentId allowed unlimited 6-digit TOTP guesses for the
        // 10-minute pending TTL with zero signal — a silent brute-force window.
        this.events.emit(MFA_FAILED, {
          type: MFA_FAILED,
          userId,
          reason: 'invalid_totp_enrollment',
          ts: Date.now(),
        });
        const attempts = this.pendingStore.incrementAttempts(enrollmentId);
        if (attempts >= MfaService.ENROLL_MAX_ATTEMPTS) {
          // Drop the pending entry on exhaustion and emit MFA_RATE_LIMITED so
          // ThreatEscalationService.onMfaRateLimited (phase 14 plan 03) counts
          // the brute-force attempt against the threat ladder.
          this.pendingStore.delete(enrollmentId);
          this.events.emit(MFA_RATE_LIMITED, {
            type: MFA_RATE_LIMITED,
            userId,
            reason: 'enrollment_attempts_exhausted',
            ts: Date.now(),
          });
        }
        // D-04: keep pending entry available for retry within TTL while under cap.
        return { ok: false, reason: 'invalid_totp' };
      }

      // Encrypt at rest (D-15) before persisting
      const encrypted = aesGcmEncrypt(pending.secret, this.encryptionKey);
      await this.secretsRepo.save(userId, encrypted);

      // Pitfall 1: drop pending entry on success
      this.pendingStore.delete(enrollmentId);

      // Audit trail: new TOTP device registered is a high-value security event
      this.events.emit(MFA_ENROLLMENT_CONFIRMED, {
        type: MFA_ENROLLMENT_CONFIRMED,
        userId,
        ts: Date.now(),
      });
      return { ok: true };
    } catch {
      return { ok: false, reason: 'internal' };
    }
  }

  /**
   * Phase 11 — Admin-triggered enrollment reset (D-07, T-11-04).
   *
   * Deletes the user_secrets row and emits MFA_ENROLLMENT_RESET so audit/observability
   * can record the privilege-bearing action. Does NOT invalidate live MFA JWTs — those
   * expire naturally via mfa_tokens.expires_at (D-08).
   *
   * Authorization is enforced upstream at the controller (method-level @Roles('admin')).
   */
  async deleteEnrollment(userId: string): Promise<MfaDeleteEnrollmentResult> {
    try {
      const deleted = await this.secretsRepo.deleteByUserId(userId);
      // Emit on every call (deleted true or false) so admin reset attempts are auditable
      this.events.emit(MFA_ENROLLMENT_RESET, {
        type: MFA_ENROLLMENT_RESET,
        userId,
        deleted,
        ts: Date.now(),
      });
      return { ok: true, deleted };
    } catch {
      return { ok: false, reason: 'internal' };
    }
  }
}
