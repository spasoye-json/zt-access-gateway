import type { TrustConfig } from '../config/slices';
import type { TrustContext } from './trust-context';
import type { TrustTelemetryRepository } from './trust-telemetry.repository';
import type { SignalAdjustment } from './trust-signal-provider.interface';

/**
 * A Signal Rule produces a Trust Signal via a numeric repository query
 * compared against a threshold. See CONTEXT.md.
 *
 * Rules with custom logic (string equality, statistical scoring, event
 * emission) are Trust Signal Providers instead — they don't fit this shape.
 *
 * `whenMet` / `whenUnmet` are deliberately neutral: which branch is
 * trust-favourable depends on the rule. For reputation rules, `whenMet`
 * (count of prior allows ≥ threshold) is favourable. For request_frequency,
 * `whenMet` (count above normal max) is unfavourable.
 */
export interface SignalRule {
  readonly name: string;
  readonly decayable: boolean;
  readonly query: (
    repo: TrustTelemetryRepository,
    ctx: TrustContext,
    config: TrustConfig,
  ) => Promise<number>;
  readonly threshold: (config: TrustConfig) => number;
  readonly compare: 'gte' | 'gt';
  readonly whenMet: { readonly delta: number; readonly reason: string };
  readonly whenUnmet: { readonly delta: number; readonly reason: string };
}

export const SIGNAL_RULES: readonly SignalRule[] = [
  {
    name: 'device_reputation',
    decayable: true,
    query: (repo, ctx) => repo.countAllowsForUserDeviceIp(ctx.userId, ctx.deviceId, ctx.ip),
    threshold: (c) => c.knownThreshold,
    compare: 'gte',
    whenMet: { delta: -0.15, reason: 'device_known' },
    whenUnmet: { delta: 0.15, reason: 'device_unknown' },
  },
  {
    name: 'ip_reputation',
    decayable: true,
    query: (repo, ctx) => repo.sumAllowsForUserIp(ctx.userId, ctx.ip),
    threshold: (c) => c.knownThreshold,
    compare: 'gte',
    whenMet: { delta: -0.15, reason: 'ip_trusted' },
    whenUnmet: { delta: 0.15, reason: 'ip_untrusted' },
  },
  {
    name: 'request_frequency',
    // request_frequency's window-bounded check can't go stale: the next
    // request re-evaluates within a fresh window. Decay would double-count.
    decayable: false,
    query: async (repo, ctx, config) => {
      const now = ctx.requestTimestamp ?? new Date();
      const since = new Date(now.getTime() - config.frequencyWindowMs);
      return repo.countActivitySince(ctx.userId, since);
    },
    threshold: (c) => c.frequencyNormalMax,
    compare: 'gt',
    whenMet: { delta: 0.2, reason: 'frequency_burst' },
    whenUnmet: { delta: -0.1, reason: 'frequency_normal' },
  },
];

export async function evaluateRule(
  rule: SignalRule,
  repo: TrustTelemetryRepository,
  config: TrustConfig,
  ctx: TrustContext,
): Promise<SignalAdjustment> {
  const value = await rule.query(repo, ctx, config);
  const threshold = rule.threshold(config);
  const matches = rule.compare === 'gte' ? value >= threshold : value > threshold;
  const outcome = matches ? rule.whenMet : rule.whenUnmet;
  return {
    source: rule.name,
    delta: outcome.delta,
    reason: outcome.reason,
    decayable: rule.decayable,
  };
}
