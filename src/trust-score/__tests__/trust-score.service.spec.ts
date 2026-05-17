import { TrustScoreService } from '../trust-score.service';
import { FingerprintStore } from '../../fingerprint/fingerprint.store';
import type { TrustTelemetryRepository } from '../trust-telemetry.repository';
import type { TrustContext } from '../trust-context';
import type { TrustConfig } from '../../config/slices';
import type { SignalRule } from '../signal-rules';
import type { Ja4hDriftProvider } from '../providers/ja4h-drift.provider';
import type { TrustDecayProvider } from '../providers/trust-decay.provider';
import type { BehaviorAnomalyProvider } from '../providers/behavior-anomaly.provider';
import type { SignalAdjustment } from '../trust-signal-provider.interface';

const config: TrustConfig = {
  knownThreshold: 3,
  decayHalfLifeMs: 60_000,
  anomalyWarmupN: 10,
  frequencyWindowMs: 60_000,
  frequencyNormalMax: 30,
};

const ctx: TrustContext = {
  userId: 'u1',
  deviceId: 'd1',
  ip: '10.0.0.1',
  ja4h: 'abc123',
};

function stubAdjustment(source: string, delta = 0): SignalAdjustment {
  return { source, delta, reason: `${source}_stub`, decayable: false };
}

function stubProvider(source: string, delta = 0) {
  return { name: source, compute: jest.fn().mockResolvedValue(stubAdjustment(source, delta)) };
}

function throwingProvider(source: string) {
  return { name: source, compute: jest.fn().mockRejectedValue(new Error('boom')) };
}

function stubDecay(delta = 0) {
  return {
    name: 'trust_decay',
    attenuate: jest.fn().mockResolvedValue(stubAdjustment('trust_decay', delta)),
  };
}

function throwingDecay() {
  return { name: 'trust_decay', attenuate: jest.fn().mockRejectedValue(new Error('boom')) };
}

function build(opts: {
  isTerminal?: boolean;
  rules?: readonly SignalRule[];
  ja4h?: ReturnType<typeof stubProvider>;
  decay?: ReturnType<typeof stubDecay>;
  anomaly?: ReturnType<typeof stubProvider>;
  telemetry?: Partial<TrustTelemetryRepository>;
}) {
  const store = {
    isTerminal: jest.fn().mockReturnValue(opts.isTerminal ?? false),
  } as unknown as FingerprintStore;
  const telemetry = (opts.telemetry ?? {}) as TrustTelemetryRepository;
  const ja4h = (opts.ja4h ?? stubProvider('ja4h_drift', 0)) as unknown as Ja4hDriftProvider;
  const decay = (opts.decay ?? stubDecay(0)) as unknown as TrustDecayProvider;
  const anomaly = (opts.anomaly ??
    stubProvider('behavior_anomaly', 0)) as unknown as BehaviorAnomalyProvider;
  const service = new TrustScoreService(
    store,
    telemetry,
    config,
    opts.rules ?? [],
    ja4h,
    decay,
    anomaly,
  );
  return { service, store, telemetry, ja4h, decay, anomaly };
}

describe('TrustScoreService', () => {
  it('returns 1.0 when FingerprintStore.isTerminal is true (no repo reads)', async () => {
    const telemetry = { getSignalRow: jest.fn() } as unknown as TrustTelemetryRepository;
    const { service } = build({ isTerminal: true, telemetry });

    const score = await service.evaluateScore(ctx);

    expect(score).toBe(1);
    expect(telemetry.getSignalRow).not.toHaveBeenCalled();
  });

  it('returns 0.5 when non-terminal with no rules and all providers return delta 0', async () => {
    const { service } = build({});
    expect(await service.evaluateScore(ctx)).toBe(0.5);
  });

  it('adds +0.1 bias when a custom provider throws (D-08)', async () => {
    const { service } = build({ ja4h: throwingProvider('ja4h_drift') });
    expect(await service.evaluateScore(ctx)).toBe(0.6);
  });

  it('adds +0.1 bias when Trust Decay throws', async () => {
    const { service } = build({ decay: throwingDecay() });
    expect(await service.evaluateScore(ctx)).toBe(0.6);
  });

  it('passes phase-1 adjustments into Trust Decay for attenuation', async () => {
    const decay = stubDecay(0);
    const { service } = build({
      ja4h: stubProvider('ja4h_drift', -0.05),
      decay,
    });
    await service.evaluateScore(ctx);
    expect(decay.attenuate).toHaveBeenCalledTimes(1);
    const phase1 = decay.attenuate.mock.calls[0][1] as SignalAdjustment[];
    expect(phase1.some((a) => a.source === 'ja4h_drift' && a.delta === -0.05)).toBe(true);
  });

  it('adds +0.1 bias when a rule query throws', async () => {
    const failingRule: SignalRule = {
      name: 'fake_rule',
      decayable: false,
      query: jest.fn().mockRejectedValue(new Error('boom')),
      threshold: () => 0,
      compare: 'gt',
      whenMet: { delta: 0, reason: 'm' },
      whenUnmet: { delta: 0, reason: 'u' },
    };
    const { service } = build({ rules: [failingRule] });
    expect(await service.evaluateScore(ctx)).toBe(0.6);
  });

  it('sums rule and provider deltas around the 0.5 baseline', async () => {
    const repo = {
      countAllowsForUserDeviceIp: jest.fn().mockResolvedValue(0),
      sumAllowsForUserIp: jest.fn().mockResolvedValue(0),
    } as unknown as TrustTelemetryRepository;
    // Use two real reputation rules → both unfavourable → +0.15 +0.15 = +0.3
    const { SIGNAL_RULES } = await import('../signal-rules');
    const reputationRules = SIGNAL_RULES.filter(
      (r) => r.name === 'device_reputation' || r.name === 'ip_reputation',
    );
    const { service } = build({ rules: reputationRules, telemetry: repo });

    expect(await service.evaluateScore(ctx)).toBe(0.8);
  });

  it('clamps to [0,1] when summed deltas exceed the range', async () => {
    const huge: SignalRule = {
      name: 'huge',
      decayable: false,
      query: jest.fn().mockResolvedValue(1),
      threshold: () => 0,
      compare: 'gt',
      whenMet: { delta: 5, reason: 'm' },
      whenUnmet: { delta: 0, reason: 'u' },
    };
    const { service } = build({ rules: [huge] });
    expect(await service.evaluateScore(ctx)).toBe(1);
  });
});
