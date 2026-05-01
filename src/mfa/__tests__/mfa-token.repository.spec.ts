import { Pool } from 'pg';

const describeDb = process.env.DATABASE_URL ? describe : describe.skip;

describeDb('MfaTokenRepository', () => {
  let pool: Pool;

  beforeAll(() => {
    pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 2 });
  });

  afterAll(async () => {
    await pool.end();
  });

  afterEach(async () => {
    await pool.query(`DELETE FROM mfa_tokens WHERE user_id LIKE $1`, ['test-%']);
  });

  it.todo('insertMfaToken stores jti, user_id, fingerprint_hash, expires_at (MFA-07)');
  it.todo('getMfaToken returns null for unknown jti');
  it.todo('getMfaToken returns null for expired token (expires_at <= NOW())');
  it.todo('getMfaToken returns null for revoked token (revoked_at IS NOT NULL)');
  it.todo('getMfaToken returns token row for valid, non-expired, non-revoked jti');
  it.todo('revokeMfaToken sets revoked_at timestamp');
  it.todo('insertMfaToken retries on jti uuid collision (Pitfall 3)');
});
