/**
 * Phase 11 Plan 02 — UserSecretsRepository write surface.
 * Phase B2: spec swaps "construct repo then overwrite internal pool with mock"
 * for an inline `Db` test double — repo now injects `Db` directly.
 */

import { UserSecretsRepository } from '../user-secrets.repository';
import type { Db } from '../../../db/db.port';

function buildMockDb(queryResult: { rows: unknown[]; rowCount: number | null }): jest.Mocked<Db> {
  return {
    query: jest.fn().mockResolvedValue(queryResult),
    tx: jest.fn(),
  };
}

describe('UserSecretsRepository — write surface', () => {
  describe('save(userId, encryptedSecret)', () => {
    it('ENROLL-04: issues an upsert query with parameterized $1/$2 placeholders', async () => {
      const db = buildMockDb({ rows: [], rowCount: 0 });
      const repo = new UserSecretsRepository(db);

      await repo.save('user-abc', 'enc-secret-xyz');

      expect(db.query).toHaveBeenCalledTimes(1);
      const [sql, params] = db.query.mock.calls[0] as [string, string[]];
      expect(sql).toMatch(/INSERT INTO user_secrets/i);
      expect(sql).toMatch(/ON CONFLICT \(user_id\) DO UPDATE/i);
      expect(sql).not.toMatch(/\$\{/); // no template interpolation
      expect(params).toEqual(['user-abc', 'enc-secret-xyz']);
    });

    it('ENROLL-04: returns void (Promise<void>)', async () => {
      const db = buildMockDb({ rows: [], rowCount: 1 });
      const repo = new UserSecretsRepository(db);

      const result = await repo.save('user-x', 'enc-x');
      expect(result).toBeUndefined();
    });
  });

  describe('deleteByUserId(userId)', () => {
    it('ENROLL-07: returns true when rowCount > 0 (row deleted)', async () => {
      const db = buildMockDb({ rows: [], rowCount: 1 });
      const repo = new UserSecretsRepository(db);

      const deleted = await repo.deleteByUserId('user-abc');
      expect(deleted).toBe(true);
    });

    it('ENROLL-07: returns false when rowCount is 0 (no row existed)', async () => {
      const db = buildMockDb({ rows: [], rowCount: 0 });
      const repo = new UserSecretsRepository(db);

      const deleted = await repo.deleteByUserId('nonexistent-user');
      expect(deleted).toBe(false);
    });

    it('ENROLL-07: uses parameterized SQL — userId is $1 param, not interpolated', async () => {
      const db = buildMockDb({ rows: [], rowCount: 1 });
      const repo = new UserSecretsRepository(db);

      await repo.deleteByUserId('user-del');

      const [sql, params] = db.query.mock.calls[0] as [string, string[]];
      expect(sql).toMatch(/DELETE FROM user_secrets WHERE user_id = \$1/i);
      expect(sql).not.toMatch(/\$\{/);
      expect(params).toEqual(['user-del']);
    });

    it('ENROLL-07: handles rowCount null (pg driver quirk) as false', async () => {
      const db = buildMockDb({ rows: [], rowCount: null });
      const repo = new UserSecretsRepository(db);

      const deleted = await repo.deleteByUserId('user-null');
      expect(deleted).toBe(false);
    });
  });

  describe('getEncryptedSecret — existing read path preserved', () => {
    it('still returns the encrypted secret string for an existing user', async () => {
      const db = buildMockDb({
        rows: [{ totp_secret_encrypted: 'enc-existing' }],
        rowCount: 1,
      });
      const repo = new UserSecretsRepository(db);

      const result = await repo.getEncryptedSecret('user-existing');
      expect(result).toBe('enc-existing');
    });
  });
});
