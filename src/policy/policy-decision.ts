/**
 * Phase 6 — Policy decision discriminated union (D-08).
 *
 * No throws on the hot path. Consumers branch on `decision`. Mirrors Phase 5
 * `VerifyResult` style (src/hashcash/hashcash.service.ts lines 34-47).
 */

export type PolicyDecision =
  | { decision: 'ALLOW'; reason: string; score: number; matchedSubject: string }
  | { decision: 'CHALLENGE'; reason: string; score: number; matchedSubject?: string }
  | { decision: 'DENY'; reason: string; score: number; matchedSubject?: string };
