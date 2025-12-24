import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Pool, PoolClient } from 'pg';

export interface PersistedChallenge {
  challengeId: string;
  userId: string;
  code: string;
  expiresAt: Date;
  verifiedAt: Date | null;
  metadata: Record<string, any>;
}

export interface PersistedToken {
  token: string;
  userId: string;
  challengeId: string;
  expiresAt: Date;
}

@Injectable()
export class MfaRepository implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(MfaRepository.name);
  private pool: Pool | null = null;

  constructor(private readonly configService: ConfigService) {}

  async onModuleInit(): Promise<void> {
    const connectionString = this.configService.get<string>('DATABASE_URL');
    if (!connectionString) {
      this.logger.warn('DATABASE_URL not configured; MFA persistence disabled');
      return;
    }

    this.pool = new Pool({ connectionString });
    let client: PoolClient | null = null;
    try {
      client = await this.pool.connect();
      await client.query(`
        CREATE TABLE IF NOT EXISTS mfa_challenges (
          challenge_id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          code TEXT NOT NULL,
          expires_at TIMESTAMPTZ NOT NULL,
          verified_at TIMESTAMPTZ,
          metadata JSONB NOT NULL DEFAULT '{}'::jsonb
        );
      `);
      await client.query(`
        CREATE TABLE IF NOT EXISTS mfa_tokens (
          token TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          challenge_id TEXT NOT NULL REFERENCES mfa_challenges(challenge_id) ON DELETE CASCADE,
          expires_at TIMESTAMPTZ NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
      `);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_id ON mfa_challenges(user_id);`);
      await client.query(`CREATE INDEX IF NOT EXISTS idx_mfa_tokens_user_id ON mfa_tokens(user_id);`);
      this.logger.log('MFA repository initialized (Postgres)');
    } catch (error) {
      this.logger.error(`Failed to initialize MFA repository: ${error.message}`);
      await this.pool?.end().catch(() => undefined);
      this.pool = null;
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

  private ensurePool(): Pool {
    if (!this.pool) {
      throw new Error('MFA persistence is not configured');
    }
    return this.pool;
  }

  async createChallenge(challenge: {
    challengeId: string;
    userId: string;
    code: string;
    expiresAt: Date;
    metadata: Record<string, any>;
  }): Promise<void> {
    const pool = this.ensurePool();
    await pool.query(
      `
      INSERT INTO mfa_challenges (challenge_id, user_id, code, expires_at, metadata)
      VALUES ($1, $2, $3, $4, $5::jsonb)
    `,
      [
        challenge.challengeId,
        challenge.userId,
        challenge.code,
        challenge.expiresAt.toISOString(),
        JSON.stringify(challenge.metadata ?? {}),
      ],
    );
  }

  async findChallenge(challengeId: string): Promise<PersistedChallenge | null> {
    const pool = this.ensurePool();
    const result = await pool.query(
      `
      SELECT challenge_id, user_id, code, expires_at, verified_at, metadata
      FROM mfa_challenges
      WHERE challenge_id = $1
    `,
      [challengeId],
    );
    if (result.rowCount === 0) {
      return null;
    }
    const row = result.rows[0];
    return {
      challengeId: row.challenge_id,
      userId: row.user_id,
      code: row.code,
      expiresAt: row.expires_at,
      verifiedAt: row.verified_at,
      metadata: row.metadata ?? {},
    };
  }

  async markChallengeVerified(challengeId: string): Promise<void> {
    const pool = this.ensurePool();
    await pool.query(
      `UPDATE mfa_challenges SET verified_at = NOW() WHERE challenge_id = $1`,
      [challengeId],
    );
  }

  async deleteChallenge(challengeId: string): Promise<void> {
    const pool = this.ensurePool();
    await pool.query(`DELETE FROM mfa_challenges WHERE challenge_id = $1`, [challengeId]);
  }

  async createToken(token: {
    token: string;
    userId: string;
    challengeId: string;
    expiresAt: Date;
  }): Promise<void> {
    const pool = this.ensurePool();
    await pool.query(
      `
      INSERT INTO mfa_tokens (token, user_id, challenge_id, expires_at)
      VALUES ($1, $2, $3, $4)
    `,
      [token.token, token.userId, token.challengeId, token.expiresAt.toISOString()],
    );
  }

  async findToken(token: string): Promise<PersistedToken | null> {
    const pool = this.ensurePool();
    const result = await pool.query(
      `
      SELECT token, user_id, challenge_id, expires_at
      FROM mfa_tokens
      WHERE token = $1
    `,
      [token],
    );
    if (result.rowCount === 0) {
      return null;
    }
    const row = result.rows[0];
    return {
      token: row.token,
      userId: row.user_id,
      challengeId: row.challenge_id,
      expiresAt: row.expires_at,
    };
  }

  async deleteToken(token: string): Promise<void> {
    const pool = this.ensurePool();
    await pool.query(`DELETE FROM mfa_tokens WHERE token = $1`, [token]);
  }

  async cleanupExpired(now: Date): Promise<void> {
    const pool = this.ensurePool();
    const isoNow = now.toISOString();
    await pool.query(`DELETE FROM mfa_tokens WHERE expires_at < $1`, [isoNow]);
    await pool.query(`DELETE FROM mfa_challenges WHERE expires_at < $1 AND verified_at IS NULL`, [isoNow]);
  }
}
