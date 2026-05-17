import type { TrustContext } from './trust-context';

/**
 * Per-signal contribution to the aggregate score (D-05).
 *
 * `source` identifies which Signal Rule or Trust Signal Provider produced the
 * adjustment. `decayable` marks adjustments whose favourable (negative) delta
 * should attenuate over idle time — read by Trust Decay during phase 2 of
 * aggregation. See CONTEXT.md.
 */
export interface SignalAdjustment {
  source: string;
  delta: number;
  reason: string;
  decayable: boolean;
}

/**
 * Pluggable trust signal (D-05). Implementations run in parallel via Promise.all
 * except the terminal JA4H check, which runs first in TrustScoreService.
 */
export interface TrustSignalProvider {
  readonly name: string;
  compute(ctx: TrustContext): Promise<SignalAdjustment>;
}
