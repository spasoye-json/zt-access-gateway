import { Pool } from 'pg';
import { randomUUID } from 'node:crypto';
import { MfaTokenRepository } from '../repositories/mfa-token.repository';
import { AppConfigService } from '../../config/config.service';

const describeDb = process.env.DATABASE_URL ? describe : describe.skip;
const TEST_UID = 'test-mfa-token-repo-user';
const TEST_FP = 'abc123fingerprint';

describeDb('MfaTokenRepository', () => {
  let pool: Pool;
  let repo: MfaTokenRepository;

  beforeAll(() => {
    pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 2 });
    repo = new MfaTokenRepository({
      databaseUrl: process.env.DATABASE_URL!,
    } as unknown as AppConfigService);
  });

  afterAll(async () => {
    await repo.onModuleDestroy();
    await pool.end();
  });

  afterEach(async () => {
    await pool.query(`DELETE FROM mfa_tokens WHERE user_id LIKE $1`, [`test-%`]);
  });

  it('insertMfaToken stores jti, user_id, fingerprint_hash, expires_at (MFA-07)', async () => {
    const jti = randomUUID();
    const exp = new Date(Date.now() + 600_000);
    await repo.insertMfaToken(jti, TEST_UID, TEST_FP, exp);
    const r = await pool.query(
      `SELECT user_id, fingerprint_hash FROM mfa_tokens WHERE jti = $1`,
      [jti],
    );
    expect(r.rows[0]?.user_id).toBe(TEST_UID);
    expect(r.rows[0]?.fingerprint_hash).toBe(TEST_FP);
  });

  it('getMfaToken returns null for unknown jti', async () => {
    expect(await repo.getMfaToken('unknown-jti')).toBeNull();
  });

  it('getMfaToken returns null for expired token (expires_at <= NOW())', async () => {
    const jti = randomUUID();
    const exp = new Date(Date.now() - 1000); // past
    await pool.query(
      `INSERT INTO mfa_tokens (jti, user_id, fingerprint_hash, expires_at) VALUES ($1, $2, $3, $4)`,
      [jti, TEST_UID, TEST_FP, exp],
    );
    expect(await repo.getMfaToken(jti)).toBeNull();
  });

  it('getMfaToken returns null for revoked token (revoked_at IS NOT NULL)', async () => {
    const jti = randomUUID();
    const exp = new Date(Date.now() + 600_000);
    await repo.insertMfaToken(jti, TEST_UID, TEST_FP, exp);
    await repo.revokeMfaToken(jti);
    expect(await repo.getMfaToken(jti)).toBeNull();
  });

  it('getMfaToken returns row for valid non-expired non-revoked jti', async () => {
    const jti = randomUUID();
    const exp = new Date(Date.now() + 600_000);
    await repo.insertMfaToken(jti, TEST_UID, TEST_FP, exp);
    const row = await repo.getMfaToken(jti);
    expect(row?.jti).toBe(jti);
    expect(row?.fingerprintHash).toBe(TEST_FP);
  });

  it('revokeMfaToken sets revoked_at timestamp', async () => {
    const jti = randomUUID();
    await repo.insertMfaToken(jti, TEST_UID, TEST_FP, new Date(Date.now() + 600_000));
    await repo.revokeMfaToken(jti);
    const r = await pool.query(`SELECT revoked_at FROM mfa_tokens WHERE jti = $1`, [jti]);
    expect(r.rows[0]?.revoked_at).not.toBeNull();
  });

  it('insertMfaToken retries on jti uuid collision (Pitfall 3)', async () => {
    // Simulate by pre-inserting with same jti
    const jti = randomUUID();
    const exp = new Date(Date.now() + 600_000);
    await pool.query(
      `INSERT INTO mfa_tokens (jti, user_id, fingerprint_hash, expires_at) VALUES ($1, $2, $3, $4)`,
      [jti, TEST_UID, TEST_FP, exp],
    );
    // Should NOT throw — retries with new UUID
    await expect(repo.insertMfaToken(jti, TEST_UID, TEST_FP, exp)).resolves.toBeUndefined();
  });
});
