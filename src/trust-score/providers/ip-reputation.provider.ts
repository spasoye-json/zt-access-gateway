import { Injectable } from '@nestjs/common';
import type { TrustSignalProvider, SignalAdjustment } from '../trust-signal-provider.interface';
import type { TrustContext } from '../trust-context';
import { TrustTelemetryRepository } from '../trust-telemetry.repository';
import { AppConfigService } from '../../config/config.service';

@Injectable()
export class IpReputationProvider implements TrustSignalProvider {
  readonly name = 'ip_reputation';

  constructor(
    private readonly repo: TrustTelemetryRepository,
    private readonly config: AppConfigService,
  ) {}

  async compute(ctx: TrustContext): Promise<SignalAdjustment> {
    const sum = await this.repo.sumAllowsForUserIp(ctx.userId, ctx.ip);
    const thr = this.config.trustKnownThreshold;
    if (sum >= thr) {
      return { delta: -0.15, reason: 'ip_trusted' };
    }
    return { delta: 0.15, reason: 'ip_untrusted' };
  }
}
