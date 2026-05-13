/**
 * Phase 11 Plan 02 — UserSecretsRepository write surface (RED).
 * Tests for save() and deleteByUserId() fail until methods are added in this plan.
 */

import { UserSecretsRepository } from '../user-secrets.repository';
import type { ServerConfig } from '../../../config/slices';

// Minimal mock pool that captures query calls
function buildMockPool(queryResult: { rows: unknown[]; rowCount: number }) {
  return { query: jest.fn().mockResolvedValue(queryResult), end: jest.fn() };
}

function buildConfig(): ServerConfig {
  return { databaseUrl: 'postgresql://localhost/test' } as unknown as ServerConfig;
}

describe('UserSecretsRepository — write surface', () => {
  describe('save(userId, encryptedSecret)', () => {
    it('ENROLL-04: issues an upsert query with parameterized $1/$2 placeholders', async () => {
      const pool = buildMockPool({ rows: [], rowCount: 0 });
      const repo = new UserSecretsRepository(buildConfig());
      // Replace internal pool with mock (constructor runs new Pool; we swap after)
      (repo as unknown as { pool: typeof pool }).pool = pool;

      await repo.save('user-abc', 'enc-secret-xyz');

      expect(pool.query).toHaveBeenCalledTimes(1);
      const [sql, params] = pool.query.mock.calls[0] as [string, string[]];
      expect(sql).toMatch(/INSERT INTO user_secrets/i);
      expect(sql).toMatch(/ON CONFLICT \(user_id\) DO UPDATE/i);
      expect(sql).not.toMatch(/\$\{/); // no template interpolation
      expect(params).toEqual(['user-abc', 'enc-secret-xyz']);
    });

    it('ENROLL-04: returns void (Promise<void>)', async () => {
      const pool = buildMockPool({ rows: [], rowCount: 1 });
      const repo = new UserSecretsRepository(buildConfig());
      (repo as unknown as { pool: typeof pool }).pool = pool;

      const result = await repo.save('user-x', 'enc-x');
      expect(result).toBeUndefined();
    });
  });

  describe('deleteByUserId(userId)', () => {
    it('ENROLL-07: returns true when rowCount > 0 (row deleted)', async () => {
      const pool = buildMockPool({ rows: [], rowCount: 1 });
      const repo = new UserSecretsRepository(buildConfig());
      (repo as unknown as { pool: typeof pool }).pool = pool;

      const deleted = await repo.deleteByUserId('user-abc');
      expect(deleted).toBe(true);
    });

    it('ENROLL-07: returns false when rowCount is 0 (no row existed)', async () => {
      const pool = buildMockPool({ rows: [], rowCount: 0 });
      const repo = new UserSecretsRepository(buildConfig());
      (repo as unknown as { pool: typeof pool }).pool = pool;

      const deleted = await repo.deleteByUserId('nonexistent-user');
      expect(deleted).toBe(false);
    });

    it('ENROLL-07: uses parameterized SQL — userId is $1 param, not interpolated', async () => {
      const pool = buildMockPool({ rows: [], rowCount: 1 });
      const repo = new UserSecretsRepository(buildConfig());
      (repo as unknown as { pool: typeof pool }).pool = pool;

      await repo.deleteByUserId('user-del');

      const [sql, params] = pool.query.mock.calls[0] as [string, string[]];
      expect(sql).toMatch(/DELETE FROM user_secrets WHERE user_id = \$1/i);
      expect(sql).not.toMatch(/\$\{/);
      expect(params).toEqual(['user-del']);
    });

    it('ENROLL-07: handles rowCount null (pg driver quirk) as false', async () => {
      const pool = buildMockPool({ rows: [], rowCount: null });
      const repo = new UserSecretsRepository(buildConfig());
      (repo as unknown as { pool: typeof pool }).pool = pool;

      const deleted = await repo.deleteByUserId('user-null');
      expect(deleted).toBe(false);
    });
  });

  describe('getEncryptedSecret — existing read path preserved', () => {
    it('still returns the encrypted secret string for an existing user', async () => {
      const pool = buildMockPool({
        rows: [{ totp_secret_encrypted: 'enc-existing' }],
        rowCount: 1,
      });
      const repo = new UserSecretsRepository(buildConfig());
      (repo as unknown as { pool: typeof pool }).pool = pool;

      const result = await repo.getEncryptedSecret('user-existing');
      expect(result).toBe('enc-existing');
    });
  });
});
