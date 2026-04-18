import type { TrustContext } from './trust-context';

/** Per-signal contribution to the aggregate score (D-05). */
export interface SignalAdjustment {
  delta: number;
  reason: string;
}

/**
 * Pluggable trust signal (D-05). Implementations run in parallel via Promise.all
 * except the terminal JA4H check, which runs first in TrustScoreService.
 */
export interface TrustSignalProvider {
  readonly name: string;
  compute(ctx: TrustContext): Promise<SignalAdjustment>;
}
