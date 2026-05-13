import { Pool } from 'pg';
import { MfaChallengeRepository } from '../repositories/mfa-challenge.repository';
import type { ServerConfig } from '../../config/slices';

const describeDb = process.env.DATABASE_URL ? describe : describe.skip;
const TEST_UID = 'test-mfa-challenge-repo-user';

describeDb('MfaChallengeRepository', () => {
  let pool: Pool;
  let repo: MfaChallengeRepository;

  beforeAll(() => {
    pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 2 });
    repo = new MfaChallengeRepository({
      databaseUrl: process.env.DATABASE_URL,
    } as unknown as ServerConfig);
  });

  afterAll(async () => {
    await repo.onModuleDestroy();
    await pool.end();
  });

  afterEach(async () => {
    await pool.query(`DELETE FROM mfa_challenges WHERE user_id LIKE $1`, [`test-%`]);
  });

  it('insertChallenge creates a row with correct user_id and expires_at (MFA-01)', async () => {
    const id = 'test-chal-1';
    const exp = new Date(Date.now() + 300_000);
    await repo.insertChallenge(id, TEST_UID, exp);
    const row = await pool.query(`SELECT user_id FROM mfa_challenges WHERE challenge_id = $1`, [
      id,
    ]);
    expect(row.rows[0]?.user_id).toBe(TEST_UID);
  });

  it('getChallenge returns null for non-existent challengeId', async () => {
    expect(await repo.getChallenge('does-not-exist')).toBeNull();
  });

  it('getChallenge returns userId and expiresAt for known challengeId', async () => {
    const id = 'test-chal-2';
    const exp = new Date(Date.now() + 300_000);
    await repo.insertChallenge(id, TEST_UID, exp);
    const result = await repo.getChallenge(id);
    expect(result?.userId).toBe(TEST_UID);
    expect(result?.expiresAt).toBeInstanceOf(Date);
  });

  // WR-05 (phase 14): atomic insert-if-under-limit.
  it('WR-05: insertChallengeIfUnderLimit inserts when count < max', async () => {
    const ok = await repo.insertChallengeIfUnderLimit(
      'test-wr05-1',
      TEST_UID,
      new Date(Date.now() + 300_000),
      60_000,
      3,
    );
    expect(ok).toBe(true);
    const r = await pool.query(`SELECT user_id FROM mfa_challenges WHERE challenge_id = $1`, [
      'test-wr05-1',
    ]);
    expect(r.rows[0]?.user_id).toBe(TEST_UID);
  });

  it('WR-05: insertChallengeIfUnderLimit returns false when count >= max (no insert)', async () => {
    // Pre-fill exactly maxCount=2 rows
    await repo.insertChallenge('test-wr05-2a', TEST_UID, new Date(Date.now() + 300_000));
    await repo.insertChallenge('test-wr05-2b', TEST_UID, new Date(Date.now() + 300_000));
    const ok = await repo.insertChallengeIfUnderLimit(
      'test-wr05-2c',
      TEST_UID,
      new Date(Date.now() + 300_000),
      60_000,
      2,
    );
    expect(ok).toBe(false);
    const r = await pool.query(`SELECT challenge_id FROM mfa_challenges WHERE challenge_id = $1`, [
      'test-wr05-2c',
    ]);
    expect(r.rows.length).toBe(0);
  });

  it('WR-05: concurrent inserts cap at maxCount even under racing callers', async () => {
    // Fire N concurrent inserts with maxCount=3. Exactly 3 should succeed.
    const fires = Array.from({ length: 10 }, (_, i) =>
      repo.insertChallengeIfUnderLimit(
        `test-wr05-race-${i}`,
        TEST_UID,
        new Date(Date.now() + 300_000),
        60_000,
        3,
      ),
    );
    const results = await Promise.all(fires);
    const successes = results.filter((r) => r === true).length;
    expect(successes).toBe(3);
    const r = await pool.query(
      `SELECT COUNT(*)::int AS c FROM mfa_challenges WHERE user_id = $1 AND challenge_id LIKE 'test-wr05-race-%'`,
      [TEST_UID],
    );
    expect(r.rows[0]?.c).toBe(3);
  });

  // WR-NEW-02 (phase 14, iter2): the prior race spec routed every worker
  // through a single shared pg.Pool (max:5). Driver-level connection multiplexing
  // can serialise the INSERTs enough that the racy SQL passes coincidentally.
  // This spec gives each worker its OWN MfaChallengeRepository (hence its own
  // pool / connection) so concurrent INSERTs actually run on independent
  // Postgres backends. Without pg_advisory_xact_lock the count + insert TOCTOU
  // reopens and successes overshoot maxCount.
  it('WR-NEW-02: concurrent inserts from INDEPENDENT connections still cap at maxCount', async () => {
    const TEST_UID_RACE = 'test-mfa-race-independent';
    await pool.query(`DELETE FROM mfa_challenges WHERE user_id = $1`, [TEST_UID_RACE]);

    const WORKERS = 12;
    const MAX = 3;
    const workerRepos: MfaChallengeRepository[] = [];
    for (let i = 0; i < WORKERS; i++) {
      workerRepos.push(
        new MfaChallengeRepository({
          databaseUrl: process.env.DATABASE_URL,
        } as unknown as ServerConfig),
      );
    }

    try {
      const fires = workerRepos.map((workerRepo, i) =>
        workerRepo.insertChallengeIfUnderLimit(
          `test-wr-new-02-race-${i}`,
          TEST_UID_RACE,
          new Date(Date.now() + 300_000),
          60_000,
          MAX,
        ),
      );
      const results = await Promise.all(fires);
      const successes = results.filter((r) => r === true).length;
      // EXACTLY MAX successes — overshoot proves the race; undershoot proves
      // accidental over-serialisation in the lock implementation.
      expect(successes).toBe(MAX);

      const r = await pool.query(
        `SELECT COUNT(*)::int AS c FROM mfa_challenges
         WHERE user_id = $1 AND challenge_id LIKE 'test-wr-new-02-race-%'`,
        [TEST_UID_RACE],
      );
      expect(r.rows[0]?.c).toBe(MAX);
    } finally {
      await Promise.all(workerRepos.map((r) => r.onModuleDestroy()));
      await pool.query(`DELETE FROM mfa_challenges WHERE user_id = $1`, [TEST_UID_RACE]);
    }
  });
});
