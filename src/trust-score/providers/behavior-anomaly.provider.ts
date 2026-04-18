import { Injectable } from '@nestjs/common';
import type { TrustSignalProvider, SignalAdjustment } from '../trust-signal-provider.interface';
import type { TrustContext } from '../trust-context';
import { TrustTelemetryRepository } from '../trust-telemetry.repository';
import { AppConfigService } from '../../config/config.service';

/**
 * D-14–D-16: hour-of-day histogram + rate EMA/variance; warmup gate; unit-weight |z| sum clamped.
 */
@Injectable()
export class BehaviorAnomalyProvider implements TrustSignalProvider {
  readonly name = 'behavior_anomaly';

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
    if (!row || row.allow_count < this.config.trustAnomalyWarmupN) {
      return { delta: 0, reason: 'anomaly_warmup' };
    }

    const hist = [...row.hour_histogram];
    while (hist.length < 24) hist.push(0);
    const now = ctx.requestTimestamp ?? new Date();
    const h = now.getUTCHours();

    const meanH =
      hist.reduce((a, b) => a + b, 0) / Math.max(1, hist.length);
    const varH =
      hist.reduce((s, v) => s + (v - meanH) ** 2, 0) / Math.max(1, hist.length);
    const stdH = Math.sqrt(varH + 1e-9);
    const zHour = stdH > 1e-6 ? Math.abs((hist[h] - meanH) / stdH) : 0;

    const interMs = Math.max(
      1,
      now.getTime() - new Date(row.last_seen_at).getTime(),
    );
    const instRate = 60000 / interMs;
    const zRate =
      Math.abs(instRate - row.rate_ema) / Math.sqrt(row.rate_ema_var + 1e-9);

    const raw = zHour + zRate;
    const delta = Math.min(0.4, Math.max(0, raw));

    return { delta, reason: 'behavior_anomaly' };
  }
}
