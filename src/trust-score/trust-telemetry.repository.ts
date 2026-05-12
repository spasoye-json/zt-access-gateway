import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { Pool, type PoolClient } from 'pg';
import { AppConfigService } from '../config/config.service';
import type { TrustContext } from './trust-context';

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

  async getSignalRow(userId: string, deviceId: string, ip: string): Promise<TrustSignalRow | null> {
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
   * Sum of allow_count across devices for this user at this IP (D-12).
   */
  async sumAllowsForUserIp(userId: string, ip: string): Promise<number> {
    const r = await this.pool.query<{ s: string }>(
      `SELECT COALESCE(SUM(allow_count), 0)::text AS s
       FROM trust_signals
       WHERE user_id = $1 AND ip = $2`,
      [userId, ip],
    );
    return Number(r.rows[0]?.s ?? 0);
  }

  /**
   * Recent ALLOW events in trust_activity for frequency signal.
   */
  async countActivitySince(userId: string, since: Date): Promise<number> {
    const r = await this.pool.query<{ c: number }>(
      `SELECT COUNT(*)::int AS c
       FROM trust_activity
       WHERE user_id = $1 AND ts > $2`,
      [userId, since],
    );
    return r.rows[0]?.c ?? 0;
  }

  /** Total rows in trust_activity (test / diagnostics). */
  async countAllTrustActivity(): Promise<number> {
    const r = await this.pool.query<{ c: number }>(`SELECT COUNT(*)::int AS c FROM trust_activity`);
    return r.rows[0]?.c ?? 0;
  }

  /**
   * ALLOW count for the (user, device, ip) tuple;0 when no row exists.
   */
  async countAllowsForUserDeviceIp(userId: string, deviceId: string, ip: string): Promise<number> {
    const row = await this.getSignalRow(userId, deviceId, ip);
    return row?.allow_count ?? 0;
  }

  /**
   * Persist post-proxy ALLOW outcome: activity row + signals UPSERT (D-20).
   * Runs in a single transaction.
   */
  async recordAllowOutcome(ctx: TrustContext, finalScore: number): Promise<void> {
    const client = await this.pool.connect();
    const ts = ctx.requestTimestamp ?? new Date();
    try {
      await client.query('BEGIN');
      await this.insertActivityRow(client, ctx, finalScore);
      await this.upsertSignalRow(client, ctx, ts);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  private async insertActivityRow(
    client: PoolClient,
    ctx: TrustContext,
    finalScore: number,
  ): Promise<void> {
    await client.query(
      `INSERT INTO trust_activity (user_id, ja4h, ip, device_id, score, decision)
       VALUES ($1, $2, $3, $4, $5, 'ALLOW')`,
      [ctx.userId, ctx.ja4h || null, ctx.ip, ctx.deviceId, finalScore],
    );
  }

  private async upsertSignalRow(client: PoolClient, ctx: TrustContext, ts: Date): Promise<void> {
    const existing = await client.query<TrustSignalRow>(
      `SELECT user_id, device_id, ip, ja4h, first_seen_at, last_seen_at,
              allow_count, hour_histogram, rate_ema, rate_ema_var, anomaly_observations
       FROM trust_signals
       WHERE user_id = $1 AND device_id = $2 AND ip = $3
       FOR UPDATE`,
      [ctx.userId, ctx.deviceId, ctx.ip],
    );

    const hr = ts.getUTCHours();
    let firstSeen: Date;
    let allowCount: number;
    let hist: number[];
    let newMean: number;
    let newVar: number;
    let nObs: number;

    if (existing.rowCount === 0) {
      firstSeen = ts;
      allowCount = 1;
      hist = new Array<number>(24).fill(0);
      hist[hr] = 1;
      newMean = 0;
      newVar = 0;
      nObs = 1;
    } else {
      const row = existing.rows[0];
      firstSeen = new Date(row.first_seen_at);
      allowCount = row.allow_count + 1;
      hist = [...row.hour_histogram];
      while (hist.length < 24) hist.push(0);
      hist[hr] = (hist[hr] ?? 0) + 1;

      const interMs = Math.max(1, ts.getTime() - new Date(row.last_seen_at).getTime());
      const instRate = 60000 / interMs;
      nObs = row.anomaly_observations + 1;
      const prevMean = row.rate_ema;
      newMean = prevMean + (instRate - prevMean) / nObs;
      newVar =
        nObs === 1
          ? 0
          : ((nObs - 2) * row.rate_ema_var + (instRate - prevMean) * (instRate - newMean)) /
            (nObs - 1);
    }

    await client.query(
      `INSERT INTO trust_signals (
         user_id, device_id, ip, ja4h, first_seen_at, last_seen_at, allow_count,
         hour_histogram, rate_ema, rate_ema_var, anomaly_observations
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::int[], $9, $10, $11)
       ON CONFLICT (user_id, device_id, ip) DO UPDATE SET
         ja4h = COALESCE(EXCLUDED.ja4h, trust_signals.ja4h),
         first_seen_at = LEAST(trust_signals.first_seen_at, EXCLUDED.first_seen_at),
         last_seen_at = EXCLUDED.last_seen_at,
         allow_count = EXCLUDED.allow_count,
         hour_histogram = EXCLUDED.hour_histogram,
         rate_ema = EXCLUDED.rate_ema,
         rate_ema_var = EXCLUDED.rate_ema_var,
         anomaly_observations = EXCLUDED.anomaly_observations`,
      [
        ctx.userId,
        ctx.deviceId,
        ctx.ip,
        ctx.ja4h || null,
        firstSeen,
        ts,
        allowCount,
        hist,
        newMean,
        newVar,
        nObs,
      ],
    );
  }
}
