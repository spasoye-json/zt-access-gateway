import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { Pool } from 'pg';
import { AppConfigService } from '../config/config.service';

/** Row shape for `trust_signals` (read model for scoring). */
export interface TrustSignalRow {
  user_id: string;
  device_id: string;
  ip: string;
  ja4h: string | null;
  first_seen_at: Date;
  last_seen_at: Date;
  allow_count: number;
  hour_histogram: number[];
  rate_ema: number;
  rate_ema_var: number;
  anomaly_observations: number;
}

@Injectable()
export class TrustTelemetryRepository implements OnModuleDestroy {
  private readonly pool: Pool;

  constructor(private readonly config: AppConfigService) {
    this.pool = new Pool({
      connectionString: this.config.databaseUrl,
      max: 5,
    });
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }

  async getSignalRow(
    userId: string,
    deviceId: string,
    ip: string,
  ): Promise<TrustSignalRow | null> {
    const r = await this.pool.query<TrustSignalRow>(
      `SELECT user_id, device_id, ip, ja4h, first_seen_at, last_seen_at,
              allow_count, hour_histogram, rate_ema, rate_ema_var, anomaly_observations
       FROM trust_signals
       WHERE user_id = $1 AND device_id = $2 AND ip = $3`,
      [userId, deviceId, ip],
    );
    return r.rows[0] ?? null;
  }

  /**
   * ALLOW count for the (user, device, ip) tuple;0 when no row exists.
   */
  async countAllowsForUserDeviceIp(
    userId: string,
    deviceId: string,
    ip: string,
  ): Promise<number> {
    const row = await this.getSignalRow(userId, deviceId, ip);
    return row?.allow_count ?? 0;
  }
}
