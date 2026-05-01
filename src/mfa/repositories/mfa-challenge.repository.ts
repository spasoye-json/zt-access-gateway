import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { Pool } from 'pg';
import { AppConfigService } from '../../config/config.service';

@Injectable()
export class MfaChallengeRepository implements OnModuleDestroy {
  private readonly pool: Pool;

  constructor(private readonly config: AppConfigService) {
    this.pool = new Pool({ connectionString: this.config.databaseUrl, max: 5 });
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }

  async insertChallenge(challengeId: string, userId: string, expiresAt: Date): Promise<void> {
    await this.pool.query(
      `INSERT INTO mfa_challenges (challenge_id, user_id, expires_at) VALUES ($1, $2, $3)`,
      [challengeId, userId, expiresAt],
    );
  }

  async getChallenge(challengeId: string): Promise<{ userId: string; expiresAt: Date } | null> {
    const r = await this.pool.query<{ user_id: string; expires_at: Date }>(
      `SELECT user_id, expires_at FROM mfa_challenges WHERE challenge_id = $1`,
      [challengeId],
    );
    if (!r.rows[0]) return null;
    return { userId: r.rows[0].user_id, expiresAt: r.rows[0].expires_at };
  }

  /**
   * Count challenges created for userId within windowMs milliseconds.
   * Used for per-user rate limiting (D-17, MFA-08).
   * Postgres INTERVAL cast: ($2::bigint * INTERVAL '1 millisecond') — Pitfall 7.
   */
  async countRecentChallenges(userId: string, windowMs: number): Promise<number> {
    const r = await this.pool.query<{ c: number }>(
      `SELECT COUNT(*)::int AS c
       FROM mfa_challenges
       WHERE user_id = $1 AND created_at > NOW() - ($2::bigint * INTERVAL '1 millisecond')`,
      [userId, windowMs],
    );
    return r.rows[0]?.c ?? 0;
  }
}
