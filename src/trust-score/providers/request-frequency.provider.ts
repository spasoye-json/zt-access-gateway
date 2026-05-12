import { Injectable } from '@nestjs/common';
import type { TrustSignalProvider, SignalAdjustment } from '../trust-signal-provider.interface';
import type { TrustContext } from '../trust-context';
import { TrustTelemetryRepository } from '../trust-telemetry.repository';
import { AppConfigService } from '../../config/config.service';

@Injectable()
export class RequestFrequencyProvider implements TrustSignalProvider {
  readonly name = 'request_frequency';

  constructor(
    private readonly repo: TrustTelemetryRepository,
    private readonly config: AppConfigService,
  ) {}

  async compute(ctx: TrustContext): Promise<SignalAdjustment> {
    const now = ctx.requestTimestamp ?? new Date();
    const since = new Date(now.getTime() - this.config.trustFrequencyWindowMs);
    const c = await this.repo.countActivitySince(ctx.userId, since);
    if (c > this.config.trustFrequencyNormalMax) {
      return { delta: 0.2, reason: 'frequency_burst' };
    }
    return { delta: -0.1, reason: 'frequency_normal' };
  }
}
