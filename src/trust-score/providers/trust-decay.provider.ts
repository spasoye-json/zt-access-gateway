import { Inject, Injectable } from '@nestjs/common';
import type { SignalAdjustment } from '../trust-signal-provider.interface';
import type { TrustContext } from '../trust-context';
import { TrustTelemetryRepository } from '../trust-telemetry.repository';
import { TRUST_CONFIG, type TrustConfig } from '../../config/slices';

/**
 * Trust Decay (post-processor; see CONTEXT.md). Runs after phase 1
 * aggregation. Attenuates each decayable + favourable Trust Signal by the
 * idle-time factor `k = exp(-idleMs / halfLife)`:
 *
 *   effective_favourable = raw_favourable * k
 *   correction           = raw_favourable * (k - 1)
 *
 * `k = 1` when idle = 0 (no correction). `k → 0` as idle grows, which makes
 * `correction → -raw_favourable` and fully cancels the favourable delta.
 *
 * Unlike Trust Signal Providers, Trust Decay produces no signal of its own
 * — only a single corrective adjustment summarising the attenuation.
 */
@Injectable()
export class TrustDecayProvider {
  readonly name = 'trust_decay';

  constructor(
    private readonly repo: TrustTelemetryRepository,
    @Inject(TRUST_CONFIG) private readonly config: TrustConfig,
  ) {}

  async attenuate(
    ctx: TrustContext,
    adjustments: readonly SignalAdjustment[],
  ): Promise<SignalAdjustment> {
    const row = await this.repo.getSignalRow(ctx.userId, ctx.deviceId, ctx.ip);
    if (!row) {
      return {
        source: this.name,
        delta: 0,
        reason: 'trust_decay_none',
        decayable: false,
      };
    }

    const now = ctx.requestTimestamp ?? new Date();
    const idleMs = Math.max(0, now.getTime() - new Date(row.last_seen_at).getTime());
    const k = Math.exp(-idleMs / this.config.decayHalfLifeMs);

    const correction = adjustments
      .filter((a) => a.decayable && a.delta < 0)
      .reduce((sum, a) => sum + a.delta * (k - 1), 0);

    return {
      source: this.name,
      delta: correction,
      reason: 'trust_decay',
      decayable: false,
    };
  }
}
