import { Inject, Injectable } from '@nestjs/common';
import type { TrustSignalProvider, SignalAdjustment } from '../trust-signal-provider.interface';
import type { TrustContext } from '../trust-context';
import { TrustTelemetryRepository } from '../trust-telemetry.repository';
import { TRUST_CONFIG, type TrustConfig } from '../../config/slices';

@Injectable()
export class DeviceReputationProvider implements TrustSignalProvider {
  readonly name = 'device_reputation';

  constructor(
    private readonly repo: TrustTelemetryRepository,
    @Inject(TRUST_CONFIG) private readonly config: TrustConfig,
  ) {}

  async compute(ctx: TrustContext): Promise<SignalAdjustment> {
    const n = await this.repo.countAllowsForUserDeviceIp(ctx.userId, ctx.deviceId, ctx.ip);
    const thr = this.config.knownThreshold;
    if (n >= thr) {
      return { source: 'device_reputation', delta: -0.15, reason: 'device_known', decayable: true };
    }
    return { source: 'device_reputation', delta: 0.15, reason: 'device_unknown', decayable: true };
  }
}
