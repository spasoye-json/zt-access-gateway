import { Inject, Injectable } from '@nestjs/common';
import type { TrustSignalProvider, SignalAdjustment } from '../trust-signal-provider.interface';
import type { TrustContext } from '../trust-context';
import { TrustTelemetryRepository } from '../trust-telemetry.repository';
import { TRUST_CONFIG, type TrustConfig } from '../../config/slices';

@Injectable()
export class IpReputationProvider implements TrustSignalProvider {
  readonly name = 'ip_reputation';

  constructor(
    private readonly repo: TrustTelemetryRepository,
    @Inject(TRUST_CONFIG) private readonly config: TrustConfig,
  ) {}

  async compute(ctx: TrustContext): Promise<SignalAdjustment> {
    const sum = await this.repo.sumAllowsForUserIp(ctx.userId, ctx.ip);
    const thr = this.config.knownThreshold;
    if (sum >= thr) {
      return { delta: -0.15, reason: 'ip_trusted' };
    }
    return { delta: 0.15, reason: 'ip_untrusted' };
  }
}
