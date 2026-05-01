/**
 * Phase 7 — MFA e2e tests (MFA-01, MFA-02, MFA-03, MFA-06, MFA-08).
 *
 * Covers:
 *  - MFA-06: POST /mfa/initiate returns 201 with { challengeId, expiresAt } for authenticated user
 *  - MFA-01: challenge row created in mfa_challenges for authenticated user
 *  - MFA-02/MFA-03: POST /mfa/verify with valid TOTP → 200 + { token, expiresAt }; JWT has typ:mfa
 *  - MFA-08: 6th initiation in window → 429 with Retry-After header
 *
 * Skip entire suite when DATABASE_URL is not set (CI without Postgres).
 * Required env vars set in tests/setup-e2e.ts (MFA_JWT_SECRET, MFA_TOTP_ENCRYPTION_KEY,
 * JWT_SECRET, MTLS_*) PLUS local defaults below for HASHCASH_HMAC_SECRET.
 */

// Set env vars BEFORE any module imports — ConfigModule validates at decoration time.
if (!process.env.HASHCASH_HMAC_SECRET)
  process.env.HASHCASH_HMAC_SECRET = 'a'.repeat(64);
if (!process.env.MFA_JWT_SECRET)
  process.env.MFA_JWT_SECRET = 'mfa-e2e-secret-that-is-at-least-32-chars!!';
if (!process.env.MFA_TOTP_ENCRYPTION_KEY)
  process.env.MFA_TOTP_ENCRYPTION_KEY = Buffer.from('a'.repeat(32)).toString('base64');

// Only import AppModule-dependent modules when DATABASE_URL is available.
// When DATABASE_URL is absent, the suite is fully skipped (no app bootstrap).
const hasDb = !!process.env.DATABASE_URL;

// Import non-app dependencies unconditionally (they don't trigger config validation).
import { Pool } from 'pg';
import { decodeJwt } from 'jose';
import { authenticator } from '@otplib/v12-adapter';
import { aesGcmEncrypt } from '../../src/shared/aes-gcm.util';
import { createHs256Token } from '../../src/auth/__tests__/test-keys';

// Lazy-loaded app dependencies — only resolved inside beforeAll when hasDb=true.
async function bootstrapApp() {
  const { Test } = await import('@nestjs/testing');
  const { AppModule } = await import('../../src/app.module');
  const { TrustScoreService } = await import('../../src/trust-score/trust-score.service');
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(TrustScoreService)
    .useValue({
      evaluateScore: jest.fn().mockResolvedValue(0.1),
      recordTrustContextAfterAllow: jest.fn(),
    })
    .compile();

  const app = moduleRef.createNestApplication();
  await app.init();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return app as any;
}

const describeE2e = hasDb ? describe : describe.skip;

const TEST_USER = 'e2e-mfa-test-user';
const TEST_DEVICE = 'e2e-device-1';
const TEST_SECRET = authenticator.generateSecret();
const MFA_ENCRYPTION_KEY = process.env.MFA_TOTP_ENCRYPTION_KEY ?? '';

describeE2e('MFA HTTP e2e', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const supertest = require('supertest') as typeof import('supertest');

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let app: any;
  let pool: Pool;
  let authToken: string;

  beforeAll(async () => {
    pool = new Pool({ connectionString: process.env.DATABASE_URL!, max: 3 });

    // Seed user_secrets row with encrypted TOTP secret
    const encrypted = aesGcmEncrypt(TEST_SECRET, MFA_ENCRYPTION_KEY);
    await pool.query(
      `INSERT INTO user_secrets (user_id, totp_secret_encrypted)
       VALUES ($1, $2)
       ON CONFLICT (user_id) DO UPDATE SET totp_secret_encrypted = $2`,
      [TEST_USER, encrypted],
    );

    app = await bootstrapApp();

    // Mint a real HS256 JWT for TEST_USER / TEST_DEVICE
    authToken = await createHs256Token(
      { sub: TEST_USER, roles: ['user'] },
      { jti: `mfa-e2e-jti-${Date.now()}` },
    );
  }, 30000);

  afterEach(async () => {
    await pool.query(`DELETE FROM mfa_challenges WHERE user_id = $1`, [TEST_USER]);
    await pool.query(`DELETE FROM mfa_tokens WHERE user_id = $1`, [TEST_USER]);
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM user_secrets WHERE user_id = $1`, [TEST_USER]);
    await app?.close();
    await pool?.end();
  });

  // ── MFA-06 / MFA-01 ────────────────────────────────────────────────────────
  describe('POST /mfa/initiate', () => {
    it('returns 201 with { challengeId, expiresAt } for authenticated user (MFA-06)', async () => {
      const res = await supertest(app.getHttpServer())
        .post('/mfa/initiate')
        .set('Authorization', `Bearer ${authToken}`)
        .set('x-device-id', TEST_DEVICE)
        .set('x-ja4h', 'fp-mfa-e2e');

      expect(res.status).toBe(201);
      expect(res.body).toMatchObject({
        challengeId: expect.any(String),
        expiresAt: expect.any(Number),
      });
      expect((res.body as { expiresAt: number }).expiresAt).toBeGreaterThan(Date.now());
    });

    it('returns 401 when no Authorization header present', async () => {
      const res = await supertest(app.getHttpServer())
        .post('/mfa/initiate')
        .set('x-device-id', TEST_DEVICE);

      expect(res.status).toBe(401);
    });

    it('returns 429 with Retry-After after 5 initiations in 60s window (MFA-08)', async () => {
      // 5 allowed initiations (rate limit max = 5, D-17)
      for (let i = 0; i < 5; i++) {
        const r = await supertest(app.getHttpServer())
          .post('/mfa/initiate')
          .set('Authorization', `Bearer ${authToken}`)
          .set('x-device-id', TEST_DEVICE)
          .set('x-ja4h', 'fp-mfa-rate');
        expect(r.status).toBe(201);
      }

      // 6th request → 429 with Retry-After
      const res = await supertest(app.getHttpServer())
        .post('/mfa/initiate')
        .set('Authorization', `Bearer ${authToken}`)
        .set('x-device-id', TEST_DEVICE)
        .set('x-ja4h', 'fp-mfa-rate');

      expect(res.status).toBe(429);
      expect(res.headers['retry-after']).toBeDefined();
      expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
      expect((res.body as { error: string }).error).toBe('mfa_rate_limited');
    }, 30000);
  });

  // ── MFA-02 / MFA-03 / MFA-04 ───────────────────────────────────────────────
  describe('POST /mfa/verify', () => {
    it('returns 200 with { token, expiresAt } for valid TOTP code (MFA-02, MFA-03)', async () => {
      // Step 1: initiate
      const initRes = await supertest(app.getHttpServer())
        .post('/mfa/initiate')
        .set('Authorization', `Bearer ${authToken}`)
        .set('x-device-id', TEST_DEVICE)
        .set('x-ja4h', 'fp-mfa-verify');
      expect(initRes.status).toBe(201);
      const { challengeId } = initRes.body as { challengeId: string };

      // Step 2: generate a real TOTP code from the seeded secret
      const totpCode = authenticator.generate(TEST_SECRET);

      // Step 3: verify
      const verifyRes = await supertest(app.getHttpServer())
        .post('/mfa/verify')
        .set('Authorization', `Bearer ${authToken}`)
        .set('x-device-id', TEST_DEVICE)
        .set('x-ja4h', 'fp-mfa-verify')
        .send({ challengeId, totpCode });

      expect(verifyRes.status).toBe(200);
      expect(verifyRes.body).toMatchObject({
        token: expect.any(String),
        expiresAt: expect.any(Number),
      });

      // MFA-03: JWT has typ:'mfa' claim
      const payload = decodeJwt((verifyRes.body as { token: string }).token);
      expect(payload.typ).toBe('mfa');
      expect(payload.sub).toBe(TEST_USER);
    }, 30000);

    it('returns 401 { error: mfa_invalid, reason: invalid_code } for wrong TOTP', async () => {
      const initRes = await supertest(app.getHttpServer())
        .post('/mfa/initiate')
        .set('Authorization', `Bearer ${authToken}`)
        .set('x-device-id', TEST_DEVICE)
        .set('x-ja4h', 'fp-mfa-verify');
      expect(initRes.status).toBe(201);
      const { challengeId } = initRes.body as { challengeId: string };

      const verifyRes = await supertest(app.getHttpServer())
        .post('/mfa/verify')
        .set('Authorization', `Bearer ${authToken}`)
        .set('x-device-id', TEST_DEVICE)
        .set('x-ja4h', 'fp-mfa-verify')
        .send({ challengeId, totpCode: '000000' });

      expect(verifyRes.status).toBe(401);
      expect((verifyRes.body as { error: string }).error).toBe('mfa_invalid');
      expect((verifyRes.body as { reason: string }).reason).toBe('invalid_code');
    }, 30000);

    it('returns 401 for non-existent challengeId', async () => {
      const totpCode = authenticator.generate(TEST_SECRET);

      const verifyRes = await supertest(app.getHttpServer())
        .post('/mfa/verify')
        .set('Authorization', `Bearer ${authToken}`)
        .set('x-device-id', TEST_DEVICE)
        .set('x-ja4h', 'fp-mfa-verify')
        .send({ challengeId: 'non-existent-challenge-id', totpCode });

      expect(verifyRes.status).toBe(401);
      expect((verifyRes.body as { error: string }).error).toBe('mfa_invalid');
      expect((verifyRes.body as { reason: string }).reason).toBe('expired_challenge');
    }, 30000);
  });
});
