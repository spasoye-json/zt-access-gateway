import type { ConfigService } from '@nestjs/config';

/**
 * Hashcash PoW slice (Phase 5 D-17).
 *
 * `hmacSecret` is separate from JWT_SECRET (D-05). Difficulty min/max are
 * the bounds for difficultyForScore(score, min, max), applied on BOTH
 * issue and verify (D-10, D-17).
 */
export interface HashcashConfig {
  /** HMAC secret for signing PoW challenge nonces. Required, min 32 chars. Separate from JWT_SECRET (D-05). */
  readonly hmacSecret: string;
  /** Challenge TTL in ms (D-03). Default 120000 (120s). */
  readonly challengeTtlMs: number;
  /** Bounded LRU capacity for the used-nonce store (D-04). Default 10000. */
  readonly usedNonceCapacity: number;
  /** Trust score above which PoW activates (D-08, strict >). Default 0.7. */
  readonly triggerThreshold: number;
  /** Minimum difficulty in bits (D-10, D-17). Default 18. */
  readonly difficultyMin: number;
  /** Maximum difficulty in bits (D-10, D-17). Default 22. */
  readonly difficultyMax: number;
}

export const HASHCASH_CONFIG = Symbol('HASHCASH_CONFIG');

export function buildHashcashConfig(env: ConfigService): HashcashConfig {
  return Object.freeze({
    hmacSecret: env.get<string>('HASHCASH_HMAC_SECRET')!,
    challengeTtlMs: env.get<number>('HASHCASH_CHALLENGE_TTL_MS')!,
    usedNonceCapacity: env.get<number>('HASHCASH_USED_NONCE_CAPACITY')!,
    triggerThreshold: env.get<number>('HASHCASH_TRIGGER_THRESHOLD')!,
    difficultyMin: env.get<number>('HASHCASH_DIFFICULTY_MIN')!,
    difficultyMax: env.get<number>('HASHCASH_DIFFICULTY_MAX')!,
  });
}
