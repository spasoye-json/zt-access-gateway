import { Injectable } from '@nestjs/common';

interface BlacklistEntry {
  expiresAt: number;
  isTerminal: boolean;
}

/**
 * In-memory blacklist for JA4H fingerprints.
 * Uses lazy eviction: expired entries are removed on the next read, not on a timer.
 * This avoids background timer overhead and keeps the store simple.
 */
@Injectable()
export class FingerprintStore {
  private readonly blacklist = new Map<string, BlacklistEntry>();

  /**
   * Add a fingerprint to the blacklist.
   * @param fingerprint - JA4H SHA-256 hex string
   * @param opts.ttlMs - How long the entry should remain active (milliseconds)
   * @param opts.isTerminal - If true, Phase 4 trust score treats this as a terminal signal (score = 1.0)
   */
  add(fingerprint: string, opts: { ttlMs: number; isTerminal: boolean }): void {
    this.blacklist.set(fingerprint, {
      expiresAt: Date.now() + opts.ttlMs,
      isTerminal: opts.isTerminal,
    });
  }

  /**
   * Returns true if the fingerprint is blacklisted and not yet expired.
   * Performs lazy eviction: if the entry has expired, it is deleted before returning false.
   */
  isBlacklisted(fingerprint: string): boolean {
    const entry = this.blacklist.get(fingerprint);
    if (!entry) return false;
    if (Date.now() >= entry.expiresAt) {
      // Lazy eviction per D-02 — removes entry so size() reflects reality over time
      this.blacklist.delete(fingerprint);
      return false;
    }
    return true;
  }

  /**
   * Returns true if the fingerprint is blacklisted, not expired, and was added with isTerminal: true.
   * Phase 4 trust scoring reads this to apply a maximum risk signal.
   */
  isTerminal(fingerprint: string): boolean {
    const entry = this.blacklist.get(fingerprint);
    if (!entry) return false;
    if (Date.now() >= entry.expiresAt) {
      this.blacklist.delete(fingerprint);
      return false;
    }
    return entry.isTerminal;
  }

  /** Returns the current number of entries (including expired until lazily evicted). */
  size(): number {
    return this.blacklist.size;
  }

  /** Clears all entries from the blacklist. */
  clear(): void {
    this.blacklist.clear();
  }
}
