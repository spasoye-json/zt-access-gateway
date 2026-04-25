/**
 * Phase 5 — Hashcash PoW pure functions (D-18).
 * No NestJS DI, no side effects. Reusable from tests, the service, and (future) client tooling.
 */
import { createHash } from 'node:crypto';

/**
 * D-10 + D-17: Map a trust score to PoW difficulty in bits.
 *
 * Generalized formula:
 *   bits = clamp(round(min + (score - 0.7) * (max - min) / 0.2), min, max)
 *
 * Production: callers pass (score, 18, 22) — yields the D-10 locked curve
 *   0.7→18, 0.8→20, 0.9→22 (and clamps outside [0.7, 0.9]).
 *
 * Test/CI: callers pass smaller bounds via HASHCASH_DIFFICULTY_MIN / MAX
 *   env (D-17). E.g. (any, 4, 4) collapses the range and yields 4 bits flat,
 *   which makes the e2e solver run in ~16 iterations.
 *
 * Score <= 0.7 is below the trigger threshold (D-08); callers should not pass it,
 * but the clamp keeps this function total.
 */
// prettier-ignore
export function difficultyForScore(score: number, min: number, max: number): number {
  const span = max - min;
  const raw = Math.round(min + ((score - 0.7) * span) / 0.2);
  if (raw < min) return min;
  if (raw > max) return max;
  return raw;
}

/**
 * D-12: Count leading zero bits in a Buffer (typically a 32-byte SHA-256 digest).
 * Iterates byte-by-byte, then bit-by-bit within the first non-zero byte.
 */
export function countLeadingZeroBits(buf: Buffer): number {
  let count = 0;
  for (const byte of buf) {
    if (byte === 0) {
      count += 8;
      continue;
    }
    let b = byte;
    while ((b & 0x80) === 0) {
      count++;
      b <<= 1;
    }
    break;
  }
  return count;
}

/**
 * D-12: SHA-256 of UTF-8 byte concatenation of nonce + solution.
 *
 * IMPORTANT: Uses string concat + 'utf8' encoding, NOT Buffer.concat.
 * Client implementations MUST match this byte sequence (Pitfall 6 in 05-RESEARCH.md).
 */
export function hashSolution(nonce: string, solution: string): Buffer {
  return createHash('sha256')
    .update(nonce + solution, 'utf8')
    .digest();
}
