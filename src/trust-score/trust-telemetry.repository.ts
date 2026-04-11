import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Pool, PoolClient } from 'pg';

export interface TrustSignalRecord {
  userId: string;
  deviceId: string;
  lastIp: string | null;
  locationFingerprint: string | null;
  lastSeenAt: Date;
}

@Injectable()
export class TrustTelemetryRepository implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(TrustTelemetryRepository.name);
  private pool: Pool | null = null;
  private enabled = false;

  constructor(private readonly configService: ConfigService) {}

  async onModuleInit(): Promise<void> {
    const nodeEnv = (this.configService.get<string>('NODE_ENV') || '').toLowerCase();
    if (nodeEnv === 'test' || this.configService.get<string>('DISABLE_DATABASE') === 'true') {
      this.logger.warn('Trust telemetry persistence disabled for tests');
      return;
    }

    const connectionString = this.configService.get<string>('DATABASE_URL');
    if (!connectionString) {
      this.logger.warn('DATABASE_URL not set; trust telemetry persistence disabled');
      return;
    }

    this.pool = new Pool({ connectionString });
    let client: PoolClient | null = null;
    try {
      client = await this.pool.connect();
      await client.query(`
        CREATE TABLE IF NOT EXISTS trust_signals (
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          last_ip TEXT,
          location_fingerprint TEXT,
          last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          PRIMARY KEY (user_id, device_id)
        );
      `);
      await client.query(`
        CREATE TABLE IF NOT EXISTS trust_activity (
          user_id TEXT NOT NULL,
          occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);
      await client.query(`
        CREATE INDEX IF NOT EXISTS idx_trust_activity_user_id ON trust_activity(user_id);
      `);
      this.enabled = true;
      this.logger.log('Trust telemetry repository initialized (Postgres)');
    } catch (error) {
      this.logger.error(`Failed to initialize trust telemetry: ${error.message}`);
      this.enabled = false;
      if (this.pool) {
        await this.pool.end().catch(() => undefined);
        this.pool = null;
      }
    } finally {
      client?.release();
    }
  }

  async onModuleDestroy(): Promise<void> {
    if (this.pool) {
      await this.pool.end().catch(() => undefined);
      this.pool = null;
    }
  }

  async getSignal(userId: string, deviceId: string): Promise<TrustSignalRecord | null> {
    if (!this.enabled || !this.pool) {
      return null;
    }

    const result = await this.pool.query(
      `SELECT user_id, device_id, last_ip, location_fingerprint, last_seen_at
       FROM trust_signals
       WHERE user_id = $1 AND device_id = $2`,
      [userId, deviceId],
    );

    if (result.rowCount === 0) {
      return null;
    }

    const row = result.rows[0];
    return {
      userId: row.user_id,
      deviceId: row.device_id,
      lastIp: row.last_ip,
      locationFingerprint: row.location_fingerprint,
      lastSeenAt: row.last_seen_at,
    };
  }

  async upsertSignal(params: {
    userId: string;
    deviceId: string;
    ip: string;
    locationFingerprint: string;
  }): Promise<void> {
    if (!this.enabled || !this.pool) {
      return;
    }

    await this.pool.query(
      `
      INSERT INTO trust_signals (user_id, device_id, last_ip, location_fingerprint, last_seen_at)
      VALUES ($1, $2, $3, $4, NOW())
      ON CONFLICT (user_id, device_id)
      DO UPDATE SET last_ip = EXCLUDED.last_ip,
                    location_fingerprint = EXCLUDED.location_fingerprint,
                    last_seen_at = NOW();
    `,
      [params.userId, params.deviceId, params.ip, params.locationFingerprint],
    );
  }

  async recordActivity(userId: string): Promise<void> {
    if (!this.enabled || !this.pool) {
      return;
    }

    await this.pool.query(`INSERT INTO trust_activity (user_id) VALUES ($1)`, [userId]);
  }

  async countRecentActivity(userId: string, windowMs: number): Promise<number> {
    if (!this.enabled || !this.pool) {
      return 0;
    }

    const result = await this.pool.query(
      `
      SELECT COUNT(*)::int AS count
      FROM trust_activity
      WHERE user_id = $1
        AND occurred_at >= NOW() - ($2::text || ' milliseconds')::interval
    `,
      [userId, windowMs],
    );

    return result.rows[0]?.count ?? 0;
  }

  async cleanupActivity(retentionMs: number): Promise<void> {
    if (!this.enabled || !this.pool) {
      return;
    }

    await this.pool.query(
      `
      DELETE FROM trust_activity
      WHERE occurred_at < NOW() - ($1::text || ' milliseconds')::interval
    `,
      [retentionMs],
    );
  }
}
