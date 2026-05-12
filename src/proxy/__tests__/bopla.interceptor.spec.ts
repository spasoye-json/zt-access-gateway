/**
 * Wave 1 GREEN tests for BoPlaInterceptor.
 * Covers: BOPL-01 (strip unauthorized fields), BOPL-02 (field-policy.json loaded at init),
 *         BOPL-03 (recursive nested + array handling), BOPL-04 (admin all-fields, lower roles restricted).
 */

jest.mock('node:fs', () => ({
  promises: { readFile: jest.fn() },
}));

const fs = require('node:fs') as { promises: { readFile: jest.Mock } };

// Import after mocking
import { BoPlaInterceptor } from '../bopla.interceptor';
import { AppConfigService } from '../../config/config.service';
import type { FieldPolicy } from '../interfaces/field-policy.interface';

/** Starter policy matching policy/field-policy.json from plan 08-00. */
const STARTER_POLICY: FieldPolicy = {
  '/users/**': { admin: ['*'], user: ['id', 'email', 'name'] },
  '/orders/**': { admin: ['*'], user: ['id', 'status', 'total'] },
  '/billing/**': { admin: ['*'] },
};

function makeInterceptor(policy: FieldPolicy = STARTER_POLICY): BoPlaInterceptor {
  const cfg = {
    boplaPolicyPath: 'policy/field-policy.json',
  } as unknown as AppConfigService;
  const interceptor = new BoPlaInterceptor(cfg);
  // Inject policy directly to bypass file I/O for strip() tests
  (interceptor as unknown as Record<string, unknown>)['fieldPolicy'] = policy;
  return interceptor;
}

describe('BoPlaInterceptor', () => {
  describe('onModuleInit (BOPL-02)', () => {
    it('reads field-policy.json from boplaPolicyPath at init', async () => {
      const cfg = { boplaPolicyPath: 'policy/field-policy.json' } as unknown as AppConfigService;
      const interceptor = new BoPlaInterceptor(cfg);
      fs.promises.readFile.mockResolvedValueOnce(JSON.stringify(STARTER_POLICY));
      await interceptor.onModuleInit();
      expect(fs.promises.readFile).toHaveBeenCalledWith('policy/field-policy.json', 'utf-8');
    });

    it('parses JSON into typed FieldPolicy structure', async () => {
      const cfg = { boplaPolicyPath: 'policy/field-policy.json' } as unknown as AppConfigService;
      const interceptor = new BoPlaInterceptor(cfg);
      fs.promises.readFile.mockResolvedValueOnce(JSON.stringify(STARTER_POLICY));
      await interceptor.onModuleInit();
      // After init, strip should work using loaded policy
      const result = interceptor.strip({ id: 1, email: 'x', secret: 's' }, '/users/profile', [
        'user',
      ]);
      expect(result).toEqual({ id: 1, email: 'x' });
    });

    it('throws on missing file (fail-fast at startup)', async () => {
      const cfg = { boplaPolicyPath: 'policy/field-policy.json' } as unknown as AppConfigService;
      const interceptor = new BoPlaInterceptor(cfg);
      const enoent = Object.assign(new Error('ENOENT: no such file'), { code: 'ENOENT' });
      fs.promises.readFile.mockRejectedValueOnce(enoent);
      await expect(interceptor.onModuleInit()).rejects.toThrow('policy/field-policy.json');
    });

    it('throws on malformed JSON', async () => {
      const cfg = { boplaPolicyPath: 'policy/field-policy.json' } as unknown as AppConfigService;
      const interceptor = new BoPlaInterceptor(cfg);
      fs.promises.readFile.mockResolvedValueOnce('{not valid json}');
      await expect(interceptor.onModuleInit()).rejects.toThrow(/JSON/i);
    });
  });

  describe('strip(data, path, roles) — admin (BOPL-04)', () => {
    it('admin role + ["*"] → returns data unchanged', () => {
      const interceptor = makeInterceptor();
      const data = { id: 1, secret: 'top-secret', nested: { a: 1 } };
      const result = interceptor.strip(data, '/users/profile', ['admin']);
      expect(result).toBe(data); // reference equality — truly unchanged
    });

    it('admin role even when no policy entry matches → returns data unchanged (D-07)', () => {
      const interceptor = makeInterceptor();
      const data = { a: 1, b: 2 };
      const result = interceptor.strip(data, '/totally/unmatched/path', ['admin']);
      expect(result).toBe(data);
    });
  });

  describe('strip(data, path, roles) — restricted role (BOPL-01)', () => {
    it('user role + ["id","email"] → object retains only id and email keys', () => {
      const interceptor = makeInterceptor();
      const result = interceptor.strip(
        { id: 1, email: 'x@example.com', secret: 'secret' },
        '/users/profile',
        ['user'],
      );
      expect(result).toEqual({ id: 1, email: 'x@example.com' });
    });

    it('user role + missing-key in allowed list → returned object lacks that key (no crash)', () => {
      const interceptor = makeInterceptor();
      const result = interceptor.strip({ id: 1 }, '/users/profile', ['user']);
      // 'email' and 'name' are in allowed list but missing from data — no crash
      expect(result).toEqual({ id: 1 });
    });
  });

  describe('strip(data, path, roles) — fail-closed (D-07)', () => {
    it('non-admin role + no matching pattern → returns {} (empty object)', () => {
      const interceptor = makeInterceptor();
      const result = interceptor.strip({ a: 1 }, '/totally/unmatched', ['user']);
      expect(result).toEqual({});
    });

    it('non-admin role + matching pattern but role not in roleMap → returns {}', () => {
      // /billing/** only has 'admin' role in starter policy
      const interceptor = makeInterceptor();
      const result = interceptor.strip({ invoiceId: 123, amount: 500 }, '/billing/invoice', [
        'user',
      ]);
      expect(result).toEqual({});
    });
  });

  describe('strip(data, path, roles) — recursive (BOPL-03)', () => {
    it('nested object — applies same allowed-fields list to nested object keys', () => {
      const policy = {
        '/data/**': { user: ['outer', 'id'] },
      };
      const interceptor = makeInterceptor(policy);
      const result = interceptor.strip(
        { outer: { id: 1, secret: 's' }, other: 'x' },
        '/data/endpoint',
        ['user'],
      );
      // 'outer' key included, recursive walk applies same allowed=['outer','id'] to nested obj
      expect(result).toEqual({ outer: { id: 1 } });
    });

    it('array of objects — applies policy to each element', () => {
      const policy = {
        '/items/**': { user: ['id'] },
      };
      const interceptor = makeInterceptor(policy);
      const result = interceptor.strip(
        [
          { id: 1, x: 'a' },
          { id: 2, x: 'b' },
        ],
        '/items/list',
        ['user'],
      );
      expect(result).toEqual([{ id: 1 }, { id: 2 }]);
    });

    it('primitive value — returned as-is', () => {
      const interceptor = makeInterceptor();
      expect(interceptor.strip(42, '/users/count', ['user'])).toBe(42);
    });
  });

  describe('strip(data, path, roles) — non-JSON safety (Pitfall 4)', () => {
    it('string body → returned as-is, no Object.entries crash', () => {
      const interceptor = makeInterceptor();
      const result = interceptor.strip('plain text response', '/users/profile', ['user']);
      expect(result).toBe('plain text response');
    });

    it('null body → returned as-is', () => {
      const interceptor = makeInterceptor();
      expect(interceptor.strip(null, '/users/profile', ['user'])).toBeNull();
    });

    it('Buffer body → returned as-is (Pitfall 4)', () => {
      const interceptor = makeInterceptor();
      const buf = Buffer.from('binary data');
      const result = interceptor.strip(buf, '/users/profile', ['user']);
      expect(result).toBe(buf);
    });
  });

  describe('first-match wins (D-06)', () => {
    it('iterates patterns in JSON declaration order; first micromatch.isMatch hit returns', () => {
      // Both /foo/** and /foo/bar match /foo/bar but the first declared wins
      const policy = {
        '/foo/**': { user: ['a'] },
        '/foo/bar': { user: ['b'] },
      };
      const interceptor = makeInterceptor(policy);
      const result = interceptor.strip({ a: 1, b: 2 }, '/foo/bar', ['user']);
      // First pattern /foo/** wins → only 'a' field
      expect(result).toEqual({ a: 1 });
    });
  });
});
