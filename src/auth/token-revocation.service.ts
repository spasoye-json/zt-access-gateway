import { Injectable } from '@nestjs/common';
import { RevocationEntry } from './interfaces/revocation-entry.interface';

/**
 * In-memory JTI blacklist for token revocation (TREV-01).
 * Uses lazy eviction: expired entries removed on next read, not on timer.
 * Pattern identical to FingerprintStore (Phase 2 D-01).
 *
 * Memory bounded by token lifetime -- entries auto-expire when the
 * original JWT would have expired (TREV-02). No unbounded growth.
 */
@Injectable()
export class TokenRevocationService {
  private readonly blacklist = new Map<string, RevocationEntry>();

  /**
   * Add a JTI to the revocation blacklist.
   * Idempotent -- revoking the same JTI twice overwrites the entry (Pitfall 7).
   * @param jti - JWT ID claim value
   * @param expiresAt - Unix timestamp in milliseconds when the original token expires
   * @param userId - Owner of the token (for D-07 ownership checks)
   */
  revoke(jti: string, expiresAt: number, userId: string): void {
    this.blacklist.set(jti, { expiresAt, userId });
  }

  /**
   * Check if a JTI has been revoked.
   * Performs lazy eviction: if the entry has expired, deletes it and returns false.
   * @param jti - JWT ID claim value
   * @returns true if jti is actively revoked (not expired)
   */
  isRevoked(jti: string): boolean {
    const entry = this.blacklist.get(jti);
    if (!entry) return false;
    if (Date.now() >= entry.expiresAt) {
      this.blacklist.delete(jti);
      return false;
    }
    return true;
  }

  /**
   * Get the revocation entry for a JTI, if active.
   * Used by AuthController for D-07 ownership checks.
   * Performs lazy eviction on expired entries.
   * @param jti - JWT ID claim value
   * @returns RevocationEntry if actively revoked, undefined otherwise
   */
  getEntry(jti: string): RevocationEntry | undefined {
    const entry = this.blacklist.get(jti);
    if (!entry) return undefined;
    if (Date.now() >= entry.expiresAt) {
      this.blacklist.delete(jti);
      return undefined;
    }
    return entry;
  }

  /** Current number of entries (including expired until lazily evicted). */
  size(): number {
    return this.blacklist.size;
  }
}
