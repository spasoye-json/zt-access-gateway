import { Injectable } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import type { TrustSignalProvider, SignalAdjustment } from '../trust-signal-provider.interface';
import type { TrustContext } from '../trust-context';
import { TrustTelemetryRepository } from '../trust-telemetry.repository';
import { FINGERPRINT_DRIFT_DETECTED } from '../../metrics/metrics-events';

@Injectable()
export class Ja4hDriftProvider implements TrustSignalProvider {
  readonly name = 'ja4h_drift';

  constructor(
    private readonly repo: TrustTelemetryRepository,
    private readonly events: EventEmitter2,
  ) {}

  async compute(ctx: TrustContext): Promise<SignalAdjustment> {
    const row = await this.repo.getSignalRow(
      ctx.userId,
      ctx.deviceId,
      ctx.ip,
    );
    if (!row || row.ja4h == null || row.ja4h === '') {
      return { delta: -0.05, reason: 'ja4h_stable' };
    }
    if (row.ja4h !== ctx.ja4h) {
      // Phase 14 Plan 01 (D-02): emit drift signal so MetricsService increments
      // zt_gateway_fingerprint_drift_total. Audit-stated "Ja4hMiddleware" location
      // is impossible — middleware runs before auth, has no prior-fingerprint state.
      this.events.emit(FINGERPRINT_DRIFT_DETECTED, {});
      return { delta: 0.3, reason: 'ja4h_drift' };
    }
    return { delta: -0.05, reason: 'ja4h_stable' };
  }
}
