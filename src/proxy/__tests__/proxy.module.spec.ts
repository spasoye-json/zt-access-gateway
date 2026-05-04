/**
 * Phase 8 Plan 04 — ProxyModule integration test.
 *
 * Bootstraps the real ProxyModule (not mocked) via Test.createTestingModule
 * and exercises four lifecycle scenarios:
 *   1. Valid env → app.init() resolves; ProxyService + BoPlaInterceptor resolvable
 *   2. Empty PROXY_SERVICE_REGISTRY ({}) → app.init() rejects with /empty/
 *   3. Malformed PROXY_SERVICE_REGISTRY (not-json) → app.init() rejects with /JSON/
 *   4. BOPLA_POLICY_PATH missing file → app.init() rejects with /policy/
 *
 * Each test uses jest.resetModules() + dynamic import so NestJS ConfigModule.forRoot
 * evaluates the Joi schema against the current process.env (not a stale cached value).
 * See policy-fail-closed.e2e.spec.ts (Phase 6 W4) for the canonical pattern.
 *
 * Threat model: T-08-04-02 — startup with bad env aborts process before serving traffic.
 */

import * as path from 'node:path';
import * as fs from 'node:fs';

/** Path to the real field-policy.json shipped in plan 08-00. */
const REAL_POLICY_PATH = path.resolve(process.cwd(), 'policy/field-policy.json');

const VALID_REGISTRY = JSON.stringify({
  users: 'https://users.test:8443',
  orders: 'https://orders.test:8443',
});

/** Minimum env vars to satisfy the Joi schema (all phases). */
function applyBaseEnv(overrides: Record<string, string> = {}): void {
  const base: Record<string, string> = {
    NODE_ENV: 'test',
    JWT_SECRET: 'test-secret-that-is-at-least-32-chars-long!',
    HASHCASH_HMAC_SECRET: 'a'.repeat(64),
    MTLS_CA_CERT_PATH: '/dev/null',
    MTLS_CLIENT_CERT_PATH: '/dev/null',
    MTLS_CLIENT_KEY_PATH: '/dev/null',
    MTLS_ALLOWED_SUBJECTS: 'cn=test',
    DATABASE_URL: 'postgresql://localhost:5432/zt_test',
    MFA_JWT_SECRET: 'mfa-test-secret-that-is-at-least-32-chars!!',
    MFA_TOTP_ENCRYPTION_KEY: Buffer.from('a'.repeat(32)).toString('base64'),
    PROXY_SERVICE_REGISTRY: VALID_REGISTRY,
    BOPLA_POLICY_PATH: REAL_POLICY_PATH,
    ...overrides,
  };
  Object.assign(process.env, base);
}

describe('ProxyModule (integration)', () => {
  // Snapshot env once before all tests so we can restore at the end.
  const ORIGINAL_PROXY_REGISTRY = process.env.PROXY_SERVICE_REGISTRY;
  const ORIGINAL_BOPLA_PATH = process.env.BOPLA_POLICY_PATH;

  afterAll(() => {
    // Best-effort restore — don't leave mutation visible to other suites.
    if (ORIGINAL_PROXY_REGISTRY !== undefined) {
      process.env.PROXY_SERVICE_REGISTRY = ORIGINAL_PROXY_REGISTRY;
    } else {
      delete process.env.PROXY_SERVICE_REGISTRY;
    }
    if (ORIGINAL_BOPLA_PATH !== undefined) {
      process.env.BOPLA_POLICY_PATH = ORIGINAL_BOPLA_PATH;
    } else {
      delete process.env.BOPLA_POLICY_PATH;
    }
  });

  it('boots with valid PROXY_SERVICE_REGISTRY and resolves ProxyService + BoPlaInterceptor', async () => {
    applyBaseEnv();
    jest.resetModules();

    const { Test } = await import('@nestjs/testing');
    const { ProxyModule } = await import('../proxy.module');
    const { ProxyService } = await import('../proxy.service');
    const { BoPlaInterceptor } = await import('../bopla.interceptor');

    const moduleRef = await Test.createTestingModule({
      imports: [ProxyModule],
    }).compile();

    const app = moduleRef.createNestApplication();
    await app.init();

    expect(app.get(ProxyService)).toBeDefined();
    expect(app.get(BoPlaInterceptor)).toBeDefined();

    await app.close();
  }, 15000);

  it('throws when PROXY_SERVICE_REGISTRY is empty {}', async () => {
    applyBaseEnv({ PROXY_SERVICE_REGISTRY: '{}' });
    jest.resetModules();

    const { Test } = await import('@nestjs/testing');
    const { ProxyModule } = await import('../proxy.module');

    const moduleRef = await Test.createTestingModule({
      imports: [ProxyModule],
    }).compile();

    const app = moduleRef.createNestApplication();
    await expect(app.init()).rejects.toThrow(/empty/i);
  }, 15000);

  it('throws when PROXY_SERVICE_REGISTRY is malformed JSON', async () => {
    applyBaseEnv({ PROXY_SERVICE_REGISTRY: 'not-json{' });
    jest.resetModules();

    const { Test } = await import('@nestjs/testing');
    const { ProxyModule } = await import('../proxy.module');

    const moduleRef = await Test.createTestingModule({
      imports: [ProxyModule],
    }).compile();

    const app = moduleRef.createNestApplication();
    await expect(app.init()).rejects.toThrow(/JSON/i);
  }, 15000);

  it('throws when BOPLA_POLICY_PATH points to a missing file', async () => {
    applyBaseEnv({ BOPLA_POLICY_PATH: '/nonexistent/field-policy.json' });
    jest.resetModules();

    const { Test } = await import('@nestjs/testing');
    const { ProxyModule } = await import('../proxy.module');

    const moduleRef = await Test.createTestingModule({
      imports: [ProxyModule],
    }).compile();

    const app = moduleRef.createNestApplication();
    await expect(app.init()).rejects.toThrow(/policy/i);
  }, 15000);
});
