import { Pool } from 'pg';

const describeDb = process.env.DATABASE_URL ? describe : describe.skip;

describeDb('MfaChallengeRepository', () => {
  let pool: Pool;

  beforeAll(() => {
    pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 2 });
  });

  afterAll(async () => {
    await pool.end();
  });

  afterEach(async () => {
    await pool.query(`DELETE FROM mfa_challenges WHERE user_id LIKE $1`, ['test-%']);
  });

  it.todo('insertChallenge creates a row with correct user_id and expires_at (MFA-01)');
  it.todo('getChallenge returns null for non-existent challengeId');
  it.todo('getChallenge returns userId and expiresAt for known challengeId');
  it.todo('countRecentChallenges returns 0 when no recent rows exist');
  it.todo('countRecentChallenges counts rows created within windowMs (MFA-08)');
});
