import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { TypedEvents } from '../shared/typed-events';
import { totp as authenticator } from '../shared/totp.util';
import { MFA_CONFIG, type MfaConfig } from '../config/slices';
import { UserSecretsRepository } from './repositories/user-secrets.repository';
import { aesGcmEncrypt } from '../shared/aes-gcm.util';
import {
  MFA_ENROLLMENT_CONFIRMED,
  MFA_ENROLLMENT_RESET,
  MFA_FAILED,
  MFA_RATE_LIMITED,
  type ThreatSignalPayload,
} from '../policy/policy-events';
import { PendingEnrollmentStore } from './enrollment.store';
import { MfaErrorRecorder } from './mfa-error-recorder.util';

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
 * Phase C (260513-mar) — MfaEnroller: the enrollment-half of the former
 * MfaService god-class. Owns TOTP enrollment lifecycle (D-01..D-10).
 *
 * Consumed only by MfaController — GatewayMiddleware does not depend on
 * enrollment, which is the whole point of the Phase C split.
 *
 * NEVER throws — all methods return discriminated unions.
 */
@Injectable()
export class MfaEnroller {
  /**
   * BL-02 (phase 14): cap on failed confirmEnrollment TOTP attempts per
   * pending-id. After exhaustion the pending entry is dropped and
   * MFA_RATE_LIMITED is emitted so ThreatEscalationService.onMfaRateLimited
   * observes the brute-force attempt.
   */
  static readonly ENROLL_MAX_ATTEMPTS = 5;

  private readonly encryptionKey: string;
  private readonly issuerName: string;

  constructor(
    @Inject(MFA_CONFIG) cfg: MfaConfig,
    private readonly secretsRepo: UserSecretsRepository,
    private readonly pendingStore: PendingEnrollmentStore,
    private readonly events: TypedEvents,
    private readonly errorRecorder: MfaErrorRecorder,
  ) {
    this.encryptionKey = cfg.totpEncryptionKey;
    this.issuerName = cfg.issuerName;
  }

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
    } catch (err) {
      this.errorRecorder.record(MfaEnroller.name, 'createEnrollment', userId, err);
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
    ip?: string,
    ja4h?: string,
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
        // IN-04 (phase 14, iter3): propagate ip + ja4h so the threat ladder
        // can correlate enrollment brute-force to a network identity (parity
        // with verifyTotp / createChallenge).
        const failPayload: ThreatSignalPayload = {
          type: MFA_FAILED,
          userId,
          reason: 'invalid_totp_enrollment',
          ts: Date.now(),
        };
        if (ip !== undefined) failPayload.ip = ip;
        if (ja4h !== undefined) failPayload.ja4h = ja4h;
        this.events.emit(MFA_FAILED, failPayload);
        const attempts = this.pendingStore.incrementAttempts(enrollmentId);
        if (attempts >= MfaEnroller.ENROLL_MAX_ATTEMPTS) {
          // Drop the pending entry on exhaustion and emit MFA_RATE_LIMITED so
          // ThreatEscalationService.onMfaRateLimited (phase 14 plan 03) counts
          // the brute-force attempt against the threat ladder.
          this.pendingStore.delete(enrollmentId);
          const rlPayload: ThreatSignalPayload = {
            type: MFA_RATE_LIMITED,
            userId,
            reason: 'enrollment_attempts_exhausted',
            ts: Date.now(),
          };
          if (ip !== undefined) rlPayload.ip = ip;
          if (ja4h !== undefined) rlPayload.ja4h = ja4h;
          this.events.emit(MFA_RATE_LIMITED, rlPayload);
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
    } catch (err) {
      this.errorRecorder.record(MfaEnroller.name, 'confirmEnrollment', userId, err);
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
    } catch (err) {
      this.errorRecorder.record(MfaEnroller.name, 'deleteEnrollment', userId, err);
      return { ok: false, reason: 'internal' };
    }
  }
}
