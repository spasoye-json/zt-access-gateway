import { Injectable } from '@nestjs/common';
import { AppConfigService } from '../config/config.service';

/**
 * Phase 5 — bounded in-memory single-use store for solved PoW nonces (D-04).
 *
 * Lazy expiry: entries past their `exp` (Unix seconds) are deleted on the next read.
 * FIFO eviction: when at capacity, the oldest entry by insertion order is dropped.
 * Map preserves insertion order, so `keys().next().value` is always the oldest.
 *
 * Cross-process replay within TTL is an accepted v1 limitation (05-RESEARCH.md "Design Risks").
 */
@Injectable()
export class UsedNonceStore {
  private readonly store = new Map<string, number>(); // nonce → expiresAt (Unix seconds)
  private readonly capacity: number;

  constructor(capacityOrConfig: number | AppConfigService = 10000) {
    this.capacity =
      typeof capacityOrConfig === 'number'
        ? capacityOrConfig
        : capacityOrConfig.hashcashUsedNonceCapacity;
  }

  /**
   * Returns true if the nonce was previously consumed and is still within its TTL.
   * Lazily evicts expired entries.
   */
  has(nonce: string): boolean {
    const exp = this.store.get(nonce);
    if (exp === undefined) return false;
    if (Math.floor(Date.now() / 1000) >= exp) {
      this.store.delete(nonce);
      return false;
    }
    return true;
  }

  /**
   * Mark a nonce as consumed. FIFO-evicts the oldest entry when at capacity.
   * `expiresAt` MUST be Unix seconds (matches nonce payload exp).
   */
  add(nonce: string, expiresAt: number): void {
    if (this.store.size >= this.capacity) {
      const oldest = this.store.keys().next().value;
      if (oldest !== undefined) this.store.delete(oldest);
    }
    this.store.set(nonce, expiresAt);
  }

  size(): number {
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }
}
