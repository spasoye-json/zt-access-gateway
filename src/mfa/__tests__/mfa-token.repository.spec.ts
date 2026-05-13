import { Pool } from 'pg';
import { randomUUID } from 'node:crypto';
import { MfaTokenRepository } from '../repositories/mfa-token.repository';
import type { ServerConfig } from '../../config/slices';

const describeDb = process.env.DATABASE_URL ? describe : describe.skip;
const TEST_UID = 'test-mfa-token-repo-user';
const TEST_FP = 'abc123fingerprint';

describeDb('MfaTokenRepository', () => {
  let pool: Pool;
  let repo: MfaTokenRepository;

  beforeAll(() => {
    pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 2 });
    repo = new MfaTokenRepository({
      databaseUrl: process.env.DATABASE_URL,
    } as unknown as ServerConfig);
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
    const r = await pool.query(`SELECT user_id, fingerprint_hash FROM mfa_tokens WHERE jti = $1`, [
      jti,
    ]);
    expect(r.rows[0]?.user_id).toBe(TEST_UID);
    expect(r.rows[0]?.fingerprint_hash).toBe(TEST_FP);
  });

  it('revokeMfaToken sets revoked_at timestamp', async () => {
    const jti = randomUUID();
    await repo.insertMfaToken(jti, TEST_UID, TEST_FP, new Date(Date.now() + 600_000));
    await repo.revokeMfaToken(jti);
    const r = await pool.query(`SELECT revoked_at FROM mfa_tokens WHERE jti = $1`, [jti]);
    expect(r.rows[0]?.revoked_at).not.toBeNull();
  });

  // WR-01 (phase 14): atomic single-SELECT returns row + flags.
  it('WR-01: getMfaTokenWithStatus returns row + isRevoked=false / isExpired=false for a fresh token', async () => {
    const jti = randomUUID();
    const exp = new Date(Date.now() + 600_000);
    await repo.insertMfaToken(jti, TEST_UID, TEST_FP, exp);
    const row = await repo.getMfaTokenWithStatus(jti);
    expect(row).not.toBeNull();
    expect(row.jti).toBe(jti);
    expect(row.fingerprintHash).toBe(TEST_FP);
    expect(row.isRevoked).toBe(false);
    expect(row.isExpired).toBe(false);
  });

  it('WR-01: getMfaTokenWithStatus returns isRevoked=true when revoked_at is set', async () => {
    const jti = randomUUID();
    const exp = new Date(Date.now() + 600_000);
    await repo.insertMfaToken(jti, TEST_UID, TEST_FP, exp);
    await repo.revokeMfaToken(jti);
    const row = await repo.getMfaTokenWithStatus(jti);
    expect(row).not.toBeNull();
    expect(row.isRevoked).toBe(true);
    expect(row.isExpired).toBe(false);
  });

  it('WR-01: getMfaTokenWithStatus returns isExpired=true for a past expires_at', async () => {
    const jti = randomUUID();
    const exp = new Date(Date.now() - 1000);
    await pool.query(
      `INSERT INTO mfa_tokens (jti, user_id, fingerprint_hash, expires_at) VALUES ($1, $2, $3, $4)`,
      [jti, TEST_UID, TEST_FP, exp],
    );
    const row = await repo.getMfaTokenWithStatus(jti);
    expect(row).not.toBeNull();
    expect(row.isExpired).toBe(true);
  });

  it('WR-01: getMfaTokenWithStatus returns null for unknown jti', async () => {
    expect(await repo.getMfaTokenWithStatus('does-not-exist')).toBeNull();
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
