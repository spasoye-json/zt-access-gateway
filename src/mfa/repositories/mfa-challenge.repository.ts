import { Inject, Injectable } from '@nestjs/common';
import { DB, type Db } from '../../db/db.port';

@Injectable()
export class MfaChallengeRepository {
  constructor(@Inject(DB) private readonly db: Db) {}

  async insertChallenge(challengeId: string, userId: string, expiresAt: Date): Promise<void> {
    await this.db.query(
      `INSERT INTO mfa_challenges (challenge_id, user_id, expires_at) VALUES ($1, $2, $3)`,
      [challengeId, userId, expiresAt],
    );
  }

  async getChallenge(challengeId: string): Promise<{ userId: string; expiresAt: Date } | null> {
    const r = await this.db.query<{ user_id: string; expires_at: Date }>(
      `SELECT user_id, expires_at FROM mfa_challenges WHERE challenge_id = $1`,
      [challengeId],
    );
    if (!r.rows[0]) return null;
    return { userId: r.rows[0].user_id, expiresAt: r.rows[0].expires_at };
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
   *
   * WR-NEW-02 (phase 14, iter2): the bare INSERT…SELECT…WHERE pattern is NOT
   * race-safe under Postgres' default READ COMMITTED isolation — each
   * concurrent statement evaluates its inner COUNT(*) against its own MVCC
   * snapshot, so two callers can each observe count < max and both insert,
   * blowing past the cap. The previous "atomic" claim was only true by virtue
   * of single-pool driver-level serialisation in tests, not the SQL.
   *
   * Fix: wrap the conditional INSERT in a transaction and acquire a
   * transaction-scoped advisory lock keyed on hashtext(userId). This
   * serialises concurrent callers operating on the SAME userId without
   * blocking unrelated users, and releases automatically on COMMIT/ROLLBACK.
   *
   * Phase B2: BEGIN/COMMIT/ROLLBACK + release are now owned by `db.tx` —
   * the lock + conditional INSERT still execute on the same PoolClient.
   */
  async insertChallengeIfUnderLimit(
    challengeId: string,
    userId: string,
    expiresAt: Date,
    windowMs: number,
    maxCount: number,
  ): Promise<boolean> {
    return this.db.tx(async (client) => {
      // hashtext(text) -> int4 — perfect for pg_advisory_xact_lock(int) and
      // partitioning concurrency by userId only.
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [userId]);
      const r = await client.query(
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
    });
  }
}
