import { Injectable } from '@nestjs/common';
import type { TrustSignalProvider, SignalAdjustment } from '../trust-signal-provider.interface';
import type { TrustContext } from '../trust-context';
import { TrustTelemetryRepository } from '../trust-telemetry.repository';

@Injectable()
export class Ja4hDriftProvider implements TrustSignalProvider {
  readonly name = 'ja4h_drift';

  constructor(private readonly repo: TrustTelemetryRepository) {}

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
      return { delta: 0.3, reason: 'ja4h_drift' };
    }
    return { delta: -0.05, reason: 'ja4h_stable' };
  }
}
