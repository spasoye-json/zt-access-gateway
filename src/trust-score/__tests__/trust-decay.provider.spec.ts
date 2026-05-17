import { TrustDecayProvider } from '../providers/trust-decay.provider';
import type { TrustTelemetryRepository } from '../trust-telemetry.repository';
import type { TrustConfig } from '../../config/slices';
import type { TrustContext } from '../trust-context';
import type { SignalAdjustment } from '../trust-signal-provider.interface';

// Despite the name, decayHalfLifeMs is used as the exponential time constant τ
// in `k = exp(-idleMs / τ)`, so after idleMs = τ, k = 1/e ≈ 0.368 (not 0.5).
const tau = 60_000;

const config: TrustConfig = {
  knownThreshold: 3,
  decayHalfLifeMs: tau,
  anomalyWarmupN: 10,
  frequencyWindowMs: 60_000,
  frequencyNormalMax: 30,
};

const now = new Date('2026-05-16T12:00:00Z');

const ctx: TrustContext = {
  userId: 'u1',
  deviceId: 'd1',
  ip: '10.0.0.1',
  ja4h: 'fp',
  requestTimestamp: now,
};

function build(row: { last_seen_at: Date } | null) {
  const repo = {
    getSignalRow: jest.fn().mockResolvedValue(row),
  } as unknown as TrustTelemetryRepository;
  return { repo, decay: new TrustDecayProvider(repo, config) };
}

function adj(source: string, delta: number, decayable: boolean): SignalAdjustment {
  return { source, delta, reason: `${source}_reason`, decayable };
}

describe('TrustDecayProvider', () => {
  it('returns trust_decay_none with delta 0 when there is no signal row', async () => {
    const { decay } = build(null);
    const out = await decay.attenuate(ctx, [adj('device_reputation', -0.15, true)]);
    expect(out).toEqual({
      source: 'trust_decay',
      delta: 0,
      reason: 'trust_decay_none',
      decayable: false,
    });
  });

  it('returns delta 0 when idleMs is 0 (k = 1, no correction)', async () => {
    const { decay } = build({ last_seen_at: now });
    const out = await decay.attenuate(ctx, [adj('device_reputation', -0.15, true)]);
    expect(out.delta).toBeCloseTo(0, 10);
    expect(out.reason).toBe('trust_decay');
  });

  it('attenuates a favourable decayable signal by (1 - 1/e) after one time-constant', async () => {
    const last = new Date(now.getTime() - tau);
    const { decay } = build({ last_seen_at: last });
    const out = await decay.attenuate(ctx, [adj('device_reputation', -0.15, true)]);
    // k = 1/e ≈ 0.368, correction = -0.15 * (1/e - 1) ≈ +0.0948
    expect(out.delta).toBeCloseTo(-0.15 * (Math.exp(-1) - 1), 10);
  });

  it('ignores non-decayable adjustments even when favourable', async () => {
    const last = new Date(now.getTime() - tau);
    const { decay } = build({ last_seen_at: last });
    const out = await decay.attenuate(ctx, [adj('request_frequency', -0.1, false)]);
    expect(out.delta).toBe(0);
  });

  it('ignores unfavourable (positive) decayable adjustments', async () => {
    const last = new Date(now.getTime() - tau);
    const { decay } = build({ last_seen_at: last });
    const out = await decay.attenuate(ctx, [adj('device_reputation', 0.15, true)]);
    expect(out.delta).toBe(0);
  });

  it('sums corrections across multiple decayable favourable adjustments', async () => {
    const last = new Date(now.getTime() - tau);
    const { decay } = build({ last_seen_at: last });
    const out = await decay.attenuate(ctx, [
      adj('device_reputation', -0.15, true),
      adj('ip_reputation', -0.15, true),
      adj('request_frequency', -0.1, false), // ignored
    ]);
    // Two favourable decayable signals at one time-constant; one non-decayable ignored.
    expect(out.delta).toBeCloseTo(2 * -0.15 * (Math.exp(-1) - 1), 10);
  });

  it('fully cancels favourable decayable signals as idle time tends to infinity', async () => {
    const last = new Date(now.getTime() - tau * 1000);
    const { decay } = build({ last_seen_at: last });
    const out = await decay.attenuate(ctx, [adj('device_reputation', -0.15, true)]);
    // k → 0, correction → +0.15
    expect(out.delta).toBeCloseTo(0.15, 6);
  });
});
