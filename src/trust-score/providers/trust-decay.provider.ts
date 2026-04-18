import { Injectable } from '@nestjs/common';
import type { TrustSignalProvider, SignalAdjustment } from '../trust-signal-provider.interface';
import type { TrustContext } from '../trust-context';
import { TrustTelemetryRepository } from '../trust-telemetry.repository';
import { AppConfigService } from '../../config/config.service';

/**
 * Applies D-13 decay as a **correction** to favorable device/ip deltas already added
 * by DeviceReputationProvider and IpReputationProvider:
 * effective_favorable = raw_favorable * exp(-idleMs / halfLife)
 * contribution here = effective_favorable - raw_favorable * (zero when idleMs = 0; relaxes toward0 when idle is long).
 */
@Injectable()
export class TrustDecayProvider implements TrustSignalProvider {
  readonly name = 'trust_decay';

  constructor(
    private readonly repo: TrustTelemetryRepository,
    private readonly config: AppConfigService,
  ) {}

  async compute(ctx: TrustContext): Promise<SignalAdjustment> {
    const row = await this.repo.getSignalRow(
      ctx.userId,
      ctx.deviceId,
      ctx.ip,
    );
    if (!row) {
      return { delta: 0, reason: 'trust_decay_none' };
    }

    const now = ctx.requestTimestamp ?? new Date();
    const idleMs = Math.max(
      0,
      now.getTime() - new Date(row.last_seen_at).getTime(),
    );
    const k = Math.exp(-idleMs / this.config.trustDecayHalfLifeMs);

    const deviceAllows = await this.repo.countAllowsForUserDeviceIp(
      ctx.userId,
      ctx.deviceId,
      ctx.ip,
    );
    const thr = this.config.trustKnownThreshold;
    const deviceRaw = deviceAllows >= thr ? -0.15 : 0.15;

    const ipSum = await this.repo.sumAllowsForUserIp(ctx.userId, ctx.ip);
    const ipRaw = ipSum >= thr ? -0.15 : 0.15;

    let correction = 0;
    if (deviceRaw < 0) {
      correction += deviceRaw * (k - 1);
    }
    if (ipRaw < 0) {
      correction += ipRaw * (k - 1);
    }

    return { delta: correction, reason: 'trust_decay' };
  }
}
