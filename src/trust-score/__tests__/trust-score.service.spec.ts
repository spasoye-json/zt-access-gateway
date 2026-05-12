import { TrustScoreService } from '../trust-score.service';
import { FingerprintStore } from '../../fingerprint/fingerprint.store';
import type { TrustTelemetryRepository } from '../trust-telemetry.repository';
import type { TrustSignalProvider } from '../trust-signal-provider.interface';
import type { TrustContext } from '../trust-context';

function stubProvider(name: string, delta: number, reason: string): TrustSignalProvider {
  return {
    name,
    compute: jest.fn().mockResolvedValue({ delta, reason }),
  };
}

function throwingProvider(name: string): TrustSignalProvider {
  return {
    name,
    compute: jest.fn().mockRejectedValue(new Error('boom')),
  };
}

describe('TrustScoreService', () => {
  const ctx: TrustContext = {
    userId: 'u1',
    deviceId: 'd1',
    ip: '10.0.0.1',
    ja4h: 'abc123',
  };

  it('returns 1.0 when FingerprintStore.isTerminal is true (no repo reads)', async () => {
    const store = { isTerminal: jest.fn().mockReturnValue(true) } as unknown as FingerprintStore;
    const telemetry = {
      getSignalRow: jest.fn(),
    } as unknown as TrustTelemetryRepository;

    const service = new TrustScoreService(
      store,
      telemetry,
      stubProvider('p1', 0, 'a') as never,
      stubProvider('p2', 0, 'b') as never,
      stubProvider('p3', 0, 'c') as never,
      stubProvider('p4', 0, 'd') as never,
      stubProvider('p5', 0, 'e') as never,
      stubProvider('p6', 0, 'f') as never,
    );

    const score = await service.evaluateScore(ctx);
    expect(score).toBe(1);
    expect(telemetry.getSignalRow).not.toHaveBeenCalled();
  });

  it('returns 0.5 when non-terminal and all providers return delta 0', async () => {
    const store = { isTerminal: jest.fn().mockReturnValue(false) } as unknown as FingerprintStore;
    const telemetry = {} as unknown as TrustTelemetryRepository;

    const service = new TrustScoreService(
      store,
      telemetry,
      stubProvider('device_reputation', 0, 'n') as never,
      stubProvider('ip_reputation', 0, 'n') as never,
      stubProvider('ja4h_drift', 0, 'n') as never,
      stubProvider('request_frequency', 0, 'n') as never,
      stubProvider('trust_decay', 0, 'n') as never,
      stubProvider('behavior_anomaly', 0, 'n') as never,
    );

    const score = await service.evaluateScore(ctx);
    expect(score).toBe(0.5);
  });

  it('adds +0.1 bias when a provider throws (D-08)', async () => {
    const store = { isTerminal: jest.fn().mockReturnValue(false) } as unknown as FingerprintStore;
    const telemetry = {} as unknown as TrustTelemetryRepository;

    const service = new TrustScoreService(
      store,
      telemetry,
      stubProvider('device_reputation', 0, 'n') as never,
      throwingProvider('ip_reputation') as never,
      stubProvider('ja4h_drift', 0, 'n') as never,
      stubProvider('request_frequency', 0, 'n') as never,
      stubProvider('trust_decay', 0, 'n') as never,
      stubProvider('behavior_anomaly', 0, 'n') as never,
    );

    const score = await service.evaluateScore(ctx);
    expect(score).toBe(0.6);
  });

  it('cold-style device+ip unknown example: +0.15 +0.15 → 0.8 with other deltas0', async () => {
    const store = { isTerminal: jest.fn().mockReturnValue(false) } as unknown as FingerprintStore;
    const telemetry = {} as unknown as TrustTelemetryRepository;

    const service = new TrustScoreService(
      store,
      telemetry,
      stubProvider('device_reputation', 0.15, 'device_unknown') as never,
      stubProvider('ip_reputation', 0.15, 'ip_untrusted') as never,
      stubProvider('ja4h_drift', 0, 'n') as never,
      stubProvider('request_frequency', 0, 'n') as never,
      stubProvider('trust_decay', 0, 'n') as never,
      stubProvider('behavior_anomaly', 0, 'n') as never,
    );

    const score = await service.evaluateScore(ctx);
    expect(score).toBe(0.8);
  });
});
