import { Injectable } from '@nestjs/common';
import type { TrustSignalProvider, SignalAdjustment } from '../trust-signal-provider.interface';
import type { TrustContext } from '../trust-context';
import { TrustTelemetryRepository } from '../trust-telemetry.repository';
import { AppConfigService } from '../../config/config.service';

@Injectable()
export class DeviceReputationProvider implements TrustSignalProvider {
  readonly name = 'device_reputation';

  constructor(
    private readonly repo: TrustTelemetryRepository,
    private readonly config: AppConfigService,
  ) {}

  async compute(ctx: TrustContext): Promise<SignalAdjustment> {
    const n = await this.repo.countAllowsForUserDeviceIp(
      ctx.userId,
      ctx.deviceId,
      ctx.ip,
    );
    const thr = this.config.trustKnownThreshold;
    if (n >= thr) {
      return { delta: -0.15, reason: 'device_known' };
    }
    return { delta: 0.15, reason: 'device_unknown' };
  }
}
