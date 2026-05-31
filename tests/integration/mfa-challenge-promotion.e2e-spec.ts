/**
 * Ticket #33 (Phase 07 — MFA challenge) — automated codification of the
 * HUMAN-UAT checklist. Three independently-runnable concerns:
 *
 *   1. FULL happy path: POST /mfa/initiate → /mfa/verify mints a REAL,
 *      fingerprint-bound MFA token; replaying it as X-MFA-Token on a request
 *      the policy answers CHALLENGE for promotes the decision to ALLOW and the
 *      (mocked) proxy is reached. Unlike gateway.e2e-spec.ts (GTWY-04) this does
 *      NOT mock MfaChallenger.validateMfaToken — the token round-trips through
 *      the real signer/validator + Postgres mfa_tokens row. Requires a live DB
 *      (skipped via describe.skip when DATABASE_URL is absent — same idiom as
 *      mfa.e2e-spec.ts).
 *
 *   2. Rate-limited /mfa/initiate → 429 with a positive Retry-After header.
 *      Driven deterministically by overriding MfaChallenger.createChallenge to
 *      report rate_limited, so the controller-owned 429 + Retry-After mapping
 *      (D-17, mfa.controller.ts) is asserted WITHOUT a live DB — always runs.
 *
 *   3. Missing/invalid MFA_* env vars fail at BOOTSTRAP (Joi validation), not at
 *      first request. Re-validates the exported production schema per-test with
 *      mutated process.env (same idiom as src/config/__tests__/config.service.spec.ts).
 *      Always runs.
 *
 * Env vars MUST be set before any AppModule-touching import — ConfigModule
 * validates at decoration time (analog: gateway.e2e-spec.ts header block).
 */

if (!process.env.HASHCASH_HMAC_SECRET) process.env.HASHCASH_HMAC_SECRET = 'a'.repeat(64);
if (!process.env.MFA_JWT_SECRET)
  process.env.MFA_JWT_SECRET = 'mfa-e2e-secret-that-is-at-least-32-chars!!';
if (!process.env.MFA_TOTP_ENCRYPTION_KEY)
  process.env.MFA_TOTP_ENCRYPTION_KEY = Buffer.from('a'.repeat(32)).toString('base64');
if (!process.env.PROXY_SERVICE_REGISTRY)
  process.env.PROXY_SERVICE_REGISTRY = JSON.stringify({ users: 'https://users.test:8443' });
if (!process.env.DATABASE_URL && process.env.RATE_LIMIT_DB_FAKE !== '0') {
  // Concerns 2 + 3 never open a real connection (proxy/audit mocked or no app at
  // all). A fake URL satisfies Joi so those suites still boot. Concern 1 gates on
  // a REAL DATABASE_URL below (hasDb) and is skipped when only this fake is present.
  process.env.DATABASE_URL_FAKE = '1';
  process.env.DATABASE_URL = 'postgresql://fake:fake@localhost:5432/fake-test-db';
}

import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { Pool } from 'pg';
import { decodeJwt } from 'jose';
import { authenticator } from '@otplib/v12-adapter';
import { validationSchema as productionSchema } from '../../src/config/config.module';
import { aesGcmEncrypt } from '../../src/shared/aes-gcm.util';
import { createHs256Token } from '../../src/auth/__tests__/test-keys';

const request = require('supertest') as typeof import('supertest');

// A real DB is required only for concern 1; the fake URL injected above is not a
// real connection string. Treat DATABASE_URL_FAKE as "no live DB".
const hasDb = !!process.env.DATABASE_URL && process.env.DATABASE_URL_FAKE !== '1';
const describeLiveDb = hasDb ? describe : describe.skip;

const TEST_USER = 'e2e-mfa-promote-user';
const TEST_DEVICE = 'e2e-promote-device-1';
const TEST_SECRET = authenticator.generateSecret();
const MFA_ENCRYPTION_KEY = process.env.MFA_TOTP_ENCRYPTION_KEY ?? '';

// ─────────────────────────────────────────────────────────────────────────────
// Concern 1 — REAL token promotes CHALLENGE → ALLOW (live DB)
// ─────────────────────────────────────────────────────────────────────────────
describeLiveDb('MFA challenge promotion — real token (#33 item 1)', () => {
  let app: INestApplication;
  let pool: Pool;
  let authToken: string;
  let forwardMock: jest.Mock;

  beforeAll(async () => {
    pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 3 });

    // Seed encrypted TOTP secret so /mfa/verify can validate a real code.
    const encrypted = aesGcmEncrypt(TEST_SECRET, MFA_ENCRYPTION_KEY);
    await pool.query(
      `INSERT INTO user_secrets (user_id, totp_secret_encrypted)
       VALUES ($1, $2)
       ON CONFLICT (user_id) DO UPDATE SET totp_secret_encrypted = $2`,
      [TEST_USER, encrypted],
    );

    const { AppModule } = await import('../../src/app.module');
    const { ProxyService } = await import('../../src/proxy/proxy.service');
    const { TrustScoreService } = await import('../../src/trust-score/trust-score.service');
    const { PolicyEvaluatorService } = await import('../../src/policy/policy-evaluator.service');

    forwardMock = jest.fn().mockResolvedValue({ status: 200, data: { id: 'u-1', ok: true } });

    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      // Avoid real mTLS to a downstream — but keep the REAL MfaChallenger so the
      // minted token is validated through the genuine signer + mfa_tokens row.
      .overrideProvider(ProxyService)
      .useValue({ forward: forwardMock, onModuleInit: jest.fn() })
      .overrideProvider(TrustScoreService)
      .useValue({
        evaluateScore: jest.fn().mockResolvedValue(0.6),
        recordTrustContextAfterAllow: jest.fn().mockResolvedValue(undefined),
      })
      // Force CHALLENGE so the MfaPromotionStage exercises the X-MFA-Token path.
      .overrideProvider(PolicyEvaluatorService)
      .useValue({
        evaluate: jest.fn().mockResolvedValue({
          decision: 'CHALLENGE',
          reason: 'risk_threshold',
          score: 0.6,
          matchedSubject: 'role:user',
        }),
        onModuleInit: jest.fn(),
        addRule: jest.fn(),
        removeRule: jest.fn(),
      })
      .compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
    await app.init();

    // JWT deviceId MUST equal the x-device-id sent at verify time so the
    // SHA-256(userId|deviceId|ip) fingerprint matches when replayed (D-05/D-06).
    authToken = await createHs256Token(
      { sub: TEST_USER, roles: ['user'], deviceId: TEST_DEVICE },
      { jti: `mfa-promote-jti-${Date.now()}` },
    );
  }, 30000);

  afterAll(async () => {
    await pool?.query(`DELETE FROM mfa_challenges WHERE user_id = $1`, [TEST_USER]);
    await pool?.query(`DELETE FROM mfa_tokens WHERE user_id = $1`, [TEST_USER]);
    await pool?.query(`DELETE FROM user_secrets WHERE user_id = $1`, [TEST_USER]);
    await app?.close();
    await pool?.end();
  });

  it('CHALLENGE request without X-MFA-Token → 401 mfa_required; proxy NOT reached', async () => {
    const res = await request(app.getHttpServer())
      .get('/users/profile')
      .set('Authorization', `Bearer ${authToken}`)
      .set('x-device-id', TEST_DEVICE);

    expect(res.status).toBe(401);
    expect(res.body).toMatchObject({ error: 'mfa_required' });
    expect(forwardMock).not.toHaveBeenCalled();
  }, 30000);

  it('initiate → verify mints a token that promotes CHALLENGE → ALLOW on retry', async () => {
    // Step 1: initiate (real challenge row).
    const initRes = await request(app.getHttpServer())
      .post('/mfa/initiate')
      .set('Authorization', `Bearer ${authToken}`)
      .set('x-device-id', TEST_DEVICE)
      .send({});
    expect(initRes.status).toBe(201);
    const { challengeId } = initRes.body as { challengeId: string };

    // Step 2: verify with a real TOTP code → real fingerprint-bound MFA token.
    const totpCode = authenticator.generate(TEST_SECRET);
    const verifyRes = await request(app.getHttpServer())
      .post('/mfa/verify')
      .set('Authorization', `Bearer ${authToken}`)
      .set('x-device-id', TEST_DEVICE)
      .send({ challengeId, totpCode });
    expect(verifyRes.status).toBe(200);
    const { token: mfaToken } = verifyRes.body as { token: string };
    expect(decodeJwt(mfaToken).typ).toBe('mfa');

    forwardMock.mockClear();

    // Step 3: replay the SAME protected request with the real X-MFA-Token. The
    // real MfaChallenger.validateMfaToken must accept it and promote to ALLOW.
    const retryRes = await request(app.getHttpServer())
      .get('/users/profile')
      .set('Authorization', `Bearer ${authToken}`)
      .set('x-device-id', TEST_DEVICE)
      .set('X-MFA-Token', mfaToken);

    expect(retryRes.status).toBe(200);
    // Promotion reached the (mocked) downstream exactly once.
    expect(forwardMock).toHaveBeenCalledTimes(1);
  }, 30000);
});

// ─────────────────────────────────────────────────────────────────────────────
// Concern 2 — Rate-limited /mfa/initiate → 429 + Retry-After (no live DB)
// ─────────────────────────────────────────────────────────────────────────────
describe('MFA rate limit — 429 + Retry-After (#33 item 2)', () => {
  let app: INestApplication;
  let authToken: string;
  const createChallengeMock = jest.fn();

  beforeAll(async () => {
    const { AppModule } = await import('../../src/app.module');
    const { MfaChallenger } = await import('../../src/mfa/mfa-challenger.service');
    const { AuditRepository } = await import('../../src/audit/audit.repository');

    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(MfaChallenger)
      .useValue({
        createChallenge: createChallengeMock,
        verifyTotp: jest.fn(),
        validateMfaToken: jest.fn(),
      })
      // /mfa/initiate is an AUTH_ONLY path: the gateway writes a best-effort
      // audit row before next()-ing to the controller. Without a live DB that
      // write exhausts the WAL and the middleware short-circuits 503
      // audit_unavailable BEFORE the controller maps the rate-limit. Override
      // the repo so the audit succeeds and the controller's 429 surfaces.
      .overrideProvider(AuditRepository)
      .useValue({
        insert: jest.fn().mockResolvedValue(undefined),
        findLogs: jest.fn().mockResolvedValue({ items: [], total: 0 }),
        onModuleDestroy: jest.fn(),
      })
      .compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
    await app.init();

    authToken = await createHs256Token(
      { sub: 'rate-user', roles: ['user'], deviceId: 'rate-device' },
      { jti: `mfa-rate-jti-${Date.now()}` },
    );
  }, 30000);

  afterAll(async () => {
    await app?.close();
  });

  it('rate_limited challenge result → 429 { error: mfa_rate_limited } + positive Retry-After', async () => {
    createChallengeMock.mockResolvedValueOnce({ ok: false, reason: 'rate_limited' });

    const res = await request(app.getHttpServer())
      .post('/mfa/initiate')
      .set('Authorization', `Bearer ${authToken}`)
      .set('x-device-id', 'rate-device')
      .send({});

    expect(res.status).toBe(429);
    expect(res.body).toMatchObject({ error: 'mfa_rate_limited' });
    expect(res.headers['retry-after']).toBeDefined();
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Concern 3 — Missing/invalid MFA_* env fails at BOOTSTRAP (Joi) (#33 item 3)
// ─────────────────────────────────────────────────────────────────────────────
describe('MFA env validation fails at bootstrap, not at first request (#33 item 3)', () => {
  let originalEnv: NodeJS.ProcessEnv;

  // Boot ONLY ConfigModule against the exported production schema. This is the
  // same validation NestJS runs at app bootstrap — a throw here proves the
  // failure is fail-fast (boot time), never deferred to a runtime request.
  async function bootConfigOnly(): Promise<void> {
    await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          ignoreEnvFile: true,
          validationSchema: productionSchema,
          validationOptions: { abortEarly: false },
        }),
      ],
    }).compile();
  }

  function setRequiredEnv(): void {
    process.env.MTLS_CA_CERT_PATH = '/tmp/ca.pem';
    process.env.MTLS_CLIENT_CERT_PATH = '/tmp/client.pem';
    process.env.MTLS_CLIENT_KEY_PATH = '/tmp/client-key.pem';
    process.env.MTLS_ALLOWED_SUBJECTS = 'test-cn';
    process.env.JWT_SECRET = 'test-secret-that-is-at-least-32-chars-long!';
    process.env.DATABASE_URL = 'postgresql://ztgateway:ztgateway@localhost:5432/ztgateway';
    process.env.HASHCASH_HMAC_SECRET = 'hashcash-secret-that-is-at-least-32-chars-long!';
    process.env.MFA_JWT_SECRET = 'mfa-secret-that-is-at-least-32-chars-long!!';
    process.env.MFA_TOTP_ENCRYPTION_KEY = Buffer.from('a'.repeat(32)).toString('base64');
    process.env.PROXY_SERVICE_REGISTRY = JSON.stringify({ dummy: 'https://dummy.test:8443' });
  }

  beforeEach(() => {
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    for (const key of Object.keys(process.env)) {
      if (!(key in originalEnv)) delete process.env[key];
    }
    Object.assign(process.env, originalEnv);
  });

  it('boots cleanly when all MFA_* vars are present and valid', async () => {
    setRequiredEnv();
    await expect(bootConfigOnly()).resolves.toBeUndefined();
  });

  it('fails to boot when MFA_JWT_SECRET is missing, naming the offending var', async () => {
    setRequiredEnv();
    delete process.env.MFA_JWT_SECRET;
    let errMsg = '';
    try {
      await bootConfigOnly();
    } catch (err) {
      errMsg = err instanceof Error ? err.message : String(err);
    }
    expect(errMsg).toContain('MFA_JWT_SECRET');
  });

  it('fails to boot when MFA_JWT_SECRET is shorter than 32 chars', async () => {
    setRequiredEnv();
    process.env.MFA_JWT_SECRET = 'too-short';
    await expect(bootConfigOnly()).rejects.toThrow();
  });

  it('fails to boot when MFA_TOTP_ENCRYPTION_KEY is missing, naming the offending var', async () => {
    setRequiredEnv();
    delete process.env.MFA_TOTP_ENCRYPTION_KEY;
    let errMsg = '';
    try {
      await bootConfigOnly();
    } catch (err) {
      errMsg = err instanceof Error ? err.message : String(err);
    }
    expect(errMsg).toContain('MFA_TOTP_ENCRYPTION_KEY');
  });

  it('fails to boot when MFA_TOTP_ENCRYPTION_KEY does not base64-decode to 32 bytes', async () => {
    setRequiredEnv();
    // 45 chars but decodes to 33 bytes — passes a naive length check, fails AES-256.
    process.env.MFA_TOTP_ENCRYPTION_KEY = 'base64-encoded-32-byte-key-here-44-chars-xxx=';
    await expect(bootConfigOnly()).rejects.toThrow();
  });

  it('fails to boot when MFA_CHALLENGE_TTL_MS >= MFA_TOKEN_TTL_MS (cross-field, D-03)', async () => {
    setRequiredEnv();
    process.env.MFA_CHALLENGE_TTL_MS = '600000';
    process.env.MFA_TOKEN_TTL_MS = '600000';
    let errMsg = '';
    try {
      await bootConfigOnly();
    } catch (err) {
      errMsg = err instanceof Error ? err.message : String(err);
    }
    expect(errMsg).toContain('MFA_CHALLENGE_TTL_MS must be < MFA_TOKEN_TTL_MS');
  });
});
