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
   *
   * NOTE (phase 14 WR-05): kept for legacy callers but the service no longer
   * uses this in the rate-limit hot path — see insertChallengeIfUnderLimit
   * which fuses count + insert into one atomic statement.
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

  /**
   * WR-05 (phase 14): atomic rate-limited insert. Inserts the challenge row
   * iff the count of rows for this userId within the past windowMs is strictly
   * less than maxCount. Returns true on insert, false when the rate limit
   * was hit. Closes the count + insert TOCTOU window where N concurrent
   * requests could each observe count < max and all insert past the cap.
   *
   * Implementation: INSERT ... SELECT $values WHERE (SELECT COUNT(*)) < $max.
   * Returns 1 affected row on success, 0 if the WHERE predicate filtered it.
   */
  async insertChallengeIfUnderLimit(
    challengeId: string,
    userId: string,
    expiresAt: Date,
    windowMs: number,
    maxCount: number,
  ): Promise<boolean> {
    const r = await this.pool.query(
      `INSERT INTO mfa_challenges (challenge_id, user_id, expires_at)
       SELECT $1, $2, $3
       WHERE (
         SELECT COUNT(*)
         FROM mfa_challenges
         WHERE user_id = $2
           AND created_at > NOW() - ($4::bigint * INTERVAL '1 millisecond')
       ) < $5`,
      [challengeId, userId, expiresAt, windowMs, maxCount],
    );
    return (r.rowCount ?? 0) > 0;
  }
}
