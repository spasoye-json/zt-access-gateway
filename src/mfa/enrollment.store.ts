import { Injectable } from '@nestjs/common';
import { AppConfigService } from '../config/config.service';

/**
 * Phase 11 — Pending TOTP enrollment entry (D-02).
 *
 * Lives ONLY in-memory for ≤ MFA_ENROLL_PENDING_TTL_MS. The base32 secret is
 * never logged, never serialized, never persisted. On confirm, the secret is
 * AES-GCM encrypted and written to user_secrets — at which point the pending
 * entry is deleted (Pitfall 1). On TTL expiry the entry is lazy-evicted on next
 * read (mirrors FingerprintStore).
 */
export interface PendingEnrollment {
  userId: string;
  secret: string;
  expiresAt: number;
}

/**
 * In-memory TTL map keyed by enrollmentId (UUIDv4). No background timers —
 * eviction happens on read (same pattern as FingerprintStore and UsedNonceStore).
 */
@Injectable()
export class PendingEnrollmentStore {
  private readonly store = new Map<string, PendingEnrollment>();
  private readonly ttlMs: number;

  constructor(cfg: AppConfigService) {
    this.ttlMs = cfg.mfaEnrollPendingTtlMs;
  }

  /**
   * Inserts or replaces a pending enrollment entry. expiresAt is computed
   * from the current time + ttlMs; re-set on the same id refreshes the deadline.
   */
  set(enrollmentId: string, entry: { userId: string; secret: string }): void {
    this.store.set(enrollmentId, {
      userId: entry.userId,
      secret: entry.secret,
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  /**
   * Returns the entry if present and not expired. Otherwise returns null
   * and lazy-evicts an expired entry from the Map (Pattern 1).
   */
  get(enrollmentId: string): PendingEnrollment | null {
    const entry = this.store.get(enrollmentId);
    if (!entry) return null;
    if (Date.now() >= entry.expiresAt) {
      this.store.delete(enrollmentId);
      return null;
    }
    return entry;
  }

  delete(enrollmentId: string): void {
    this.store.delete(enrollmentId);
  }

  /** Returns true if a non-expired pending entry exists for this userId. */
  hasPendingForUser(userId: string): boolean {
    const now = Date.now();
    for (const [id, entry] of this.store) {
      if (now >= entry.expiresAt) {
        this.store.delete(id);
        continue;
      }
      if (entry.userId === userId) return true;
    }
    return false;
  }

  /** Returns count of non-expired entries. Sweeps stale entries as a side-effect. */
  size(): number {
    const now = Date.now();
    for (const [id, entry] of this.store) {
      if (now >= entry.expiresAt) this.store.delete(id);
    }
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }
}
