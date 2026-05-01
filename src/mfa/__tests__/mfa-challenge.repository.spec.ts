import { Pool } from 'pg';
import { MfaChallengeRepository } from '../repositories/mfa-challenge.repository';
import { AppConfigService } from '../../config/config.service';

const describeDb = process.env.DATABASE_URL ? describe : describe.skip;
const TEST_UID = 'test-mfa-challenge-repo-user';

describeDb('MfaChallengeRepository', () => {
  let pool: Pool;
  let repo: MfaChallengeRepository;

  beforeAll(() => {
    pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 2 });
    repo = new MfaChallengeRepository({
      databaseUrl: process.env.DATABASE_URL!,
    } as unknown as AppConfigService);
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
    const row = await pool.query(
      `SELECT user_id FROM mfa_challenges WHERE challenge_id = $1`,
      [id],
    );
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

  it('countRecentChallenges returns 0 when no recent rows exist', async () => {
    expect(await repo.countRecentChallenges(TEST_UID, 60_000)).toBe(0);
  });

  it('countRecentChallenges counts rows created within windowMs (MFA-08)', async () => {
    await repo.insertChallenge('test-chal-3', TEST_UID, new Date(Date.now() + 300_000));
    await repo.insertChallenge('test-chal-4', TEST_UID, new Date(Date.now() + 300_000));
    const count = await repo.countRecentChallenges(TEST_UID, 60_000);
    expect(count).toBe(2);
  });
});
