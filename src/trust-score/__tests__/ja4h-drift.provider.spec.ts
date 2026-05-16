import { EventEmitter2 } from '@nestjs/event-emitter';
import { Ja4hDriftProvider } from '../providers/ja4h-drift.provider';
import { TrustTelemetryRepository } from '../trust-telemetry.repository';
import { FINGERPRINT_DRIFT_DETECTED } from '../../metrics/metrics-events';
import { TypedEvents } from '../../shared/typed-events';

describe('Ja4hDriftProvider (Phase 14 Plan 01 — drift event, D-02)', () => {
  const baseCtx = {
    userId: 'u-1',
    deviceId: 'd-1',
    ip: '1.2.3.4',
    ja4h: 'new-fp',
  } as never;

  function buildProvider(row: { ja4h: string | null }) {
    const repo = {
      getSignalRow: jest.fn().mockResolvedValue(row),
    } as unknown as TrustTelemetryRepository;
    const bus = new EventEmitter2();
    return { provider: new Ja4hDriftProvider(repo, new TypedEvents(bus)), events: bus };
  }

  it('emits FINGERPRINT_DRIFT_DETECTED when row.ja4h differs from ctx.ja4h', async () => {
    const { provider, events } = buildProvider({ ja4h: 'old-fp' });
    const listener = jest.fn();
    events.on(FINGERPRINT_DRIFT_DETECTED, listener);

    const adj = await provider.compute(baseCtx);

    expect(adj).toEqual({
      source: 'ja4h_drift',
      delta: 0.3,
      reason: 'ja4h_drift',
      decayable: false,
    });
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('does NOT emit when row.ja4h matches ctx.ja4h', async () => {
    const { provider, events } = buildProvider({ ja4h: 'new-fp' });
    const listener = jest.fn();
    events.on(FINGERPRINT_DRIFT_DETECTED, listener);

    const adj = await provider.compute(baseCtx);

    expect(adj).toEqual({
      source: 'ja4h_drift',
      delta: -0.05,
      reason: 'ja4h_stable',
      decayable: false,
    });
    expect(listener).not.toHaveBeenCalled();
  });

  it('does NOT emit when stored row has no ja4h (first sighting)', async () => {
    const { provider, events } = buildProvider({ ja4h: null });
    const listener = jest.fn();
    events.on(FINGERPRINT_DRIFT_DETECTED, listener);

    const adj = await provider.compute(baseCtx);

    expect(adj).toEqual({
      source: 'ja4h_drift',
      delta: -0.05,
      reason: 'ja4h_stable',
      decayable: false,
    });
    expect(listener).not.toHaveBeenCalled();
  });
});
