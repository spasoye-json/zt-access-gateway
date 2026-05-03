/**
 * Phase 11 — MFA Enrollment e2e tests (ENROLL-01, 03, 04, 07, 09, 10).
 * Skipped when DATABASE_URL is unset (CI sandbox).
 */
if (!process.env.HASHCASH_HMAC_SECRET) process.env.HASHCASH_HMAC_SECRET = 'a'.repeat(64);
if (!process.env.MFA_JWT_SECRET)
  process.env.MFA_JWT_SECRET = 'mfa-e2e-secret-that-is-at-least-32-chars!!';
if (!process.env.MFA_TOTP_ENCRYPTION_KEY)
  process.env.MFA_TOTP_ENCRYPTION_KEY = Buffer.from('a'.repeat(32)).toString('base64');
if (!process.env.MFA_ISSUER_NAME) process.env.MFA_ISSUER_NAME = 'ZT-Gateway';
if (!process.env.MFA_ENROLL_PENDING_TTL_MS) process.env.MFA_ENROLL_PENDING_TTL_MS = '600000';

const hasDb = !!process.env.DATABASE_URL;

import { Pool } from 'pg';
import { authenticator } from '@otplib/v12-adapter';
import { createHs256Token } from '../../src/auth/__tests__/test-keys';

async function bootstrapApp() {
  const { Test } = await import('@nestjs/testing');
  const { AppModule } = await import('../../src/app.module');
  const { TrustScoreService } = await import('../../src/trust-score/trust-score.service');
  const { ValidationPipe } = await import('@nestjs/common');
  const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(TrustScoreService)
    .useValue({
      evaluateScore: jest.fn().mockResolvedValue(0.1),
      recordTrustContextAfterAllow: jest.fn(),
    })
    .compile();
  const app = moduleRef.createNestApplication();
  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
  );
  await app.init();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return app as any;
}

const describeE2e = hasDb ? describe : describe.skip;

const TEST_USER = `enroll-e2e-${Date.now()}`;
const ADMIN_USER = `enroll-admin-${Date.now()}`;

describeE2e('MFA Enrollment HTTP e2e', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const supertest = require('supertest') as typeof import('supertest');

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let app: any;
  let pool: Pool;
  let userToken: string;
  let adminToken: string;

  beforeAll(async () => {
    pool = new Pool({ connectionString: process.env.DATABASE_URL!, max: 3 });
    await pool.query(`DELETE FROM user_secrets WHERE user_id = $1`, [TEST_USER]);
    app = await bootstrapApp();
    userToken = await createHs256Token(
      { sub: TEST_USER, roles: ['user'] },
      { jti: `enroll-e2e-jti-${Date.now()}` },
    );
    adminToken = await createHs256Token(
      { sub: ADMIN_USER, roles: ['admin'] },
      { jti: `enroll-e2e-admin-jti-${Date.now()}` },
    );
  }, 30000);

  afterEach(async () => {
    await pool.query(`DELETE FROM user_secrets WHERE user_id = $1`, [TEST_USER]);
  });

  afterAll(async () => {
    await app?.close();
    await pool?.end();
  });

  // ── ENROLL-01 ──────────────────────────────────────────────────────────────
  describe('POST /mfa/enroll', () => {
    it('ENROLL-01: returns 201 with { enrollmentId, otpauthUri } for authenticated user', async () => {
      const res = await supertest(app.getHttpServer())
        .post('/mfa/enroll')
        .set('Authorization', `Bearer ${userToken}`)
        .set('x-device-id', 'enroll-device-1')
        .set('x-ja4h', 'fp-enroll-e2e');

      expect(res.status).toBe(201);
      expect(res.body).toMatchObject({
        enrollmentId: expect.stringMatching(/^[0-9a-f-]{36}$/),
        otpauthUri: expect.stringMatching(/^otpauth:\/\/totp\//),
      });
      expect(res.body.otpauthUri).toContain('algorithm=SHA1');
      expect(res.body.otpauthUri).toContain('digits=6');
      expect(res.body.otpauthUri).toContain('period=30');
    });

    it('ENROLL-09: returns 401 when no Authorization header', async () => {
      const res = await supertest(app.getHttpServer()).post('/mfa/enroll');
      expect(res.status).toBe(401);
    });

    it('ENROLL-03: returns 409 already_enrolled on second enroll attempt', async () => {
      // first enroll → confirm to populate user_secrets
      const enrollRes = await supertest(app.getHttpServer())
        .post('/mfa/enroll')
        .set('Authorization', `Bearer ${userToken}`)
        .set('x-device-id', 'enroll-device-1');
      expect(enrollRes.status).toBe(201);
      const { enrollmentId, otpauthUri } = enrollRes.body as {
        enrollmentId: string;
        otpauthUri: string;
      };
      const secretMatch = otpauthUri.match(/secret=([^&]+)/);
      expect(secretMatch).not.toBeNull();
      const secret = secretMatch![1];
      const totp = authenticator.generate(secret);

      const confirmRes = await supertest(app.getHttpServer())
        .post('/mfa/enroll/confirm')
        .set('Authorization', `Bearer ${userToken}`)
        .set('x-device-id', 'enroll-device-1')
        .send({ enrollmentId, totpCode: totp });
      expect(confirmRes.status).toBe(200);

      // Second enroll attempt → 409
      const secondRes = await supertest(app.getHttpServer())
        .post('/mfa/enroll')
        .set('Authorization', `Bearer ${userToken}`)
        .set('x-device-id', 'enroll-device-1');
      expect(secondRes.status).toBe(409);
      expect(secondRes.body).toMatchObject({ error: 'already_enrolled' });
    });
  });

  // ── ENROLL-04 ──────────────────────────────────────────────────────────────
  describe('POST /mfa/enroll/confirm', () => {
    it('ENROLL-04: full happy path enroll → confirm with valid TOTP → 200', async () => {
      const enrollRes = await supertest(app.getHttpServer())
        .post('/mfa/enroll')
        .set('Authorization', `Bearer ${userToken}`)
        .set('x-device-id', 'enroll-device-1');
      expect(enrollRes.status).toBe(201);
      const { enrollmentId, otpauthUri } = enrollRes.body as {
        enrollmentId: string;
        otpauthUri: string;
      };
      const secret = otpauthUri.match(/secret=([^&]+)/)![1];
      const totp = authenticator.generate(secret);

      const confirmRes = await supertest(app.getHttpServer())
        .post('/mfa/enroll/confirm')
        .set('Authorization', `Bearer ${userToken}`)
        .set('x-device-id', 'enroll-device-1')
        .send({ enrollmentId, totpCode: totp });

      expect(confirmRes.status).toBe(200);

      const row = await pool.query(
        `SELECT user_id FROM user_secrets WHERE user_id = $1`,
        [TEST_USER],
      );
      expect(row.rowCount).toBe(1);
    });

    it('ENROLL-05: returns 400 invalid_totp on wrong code', async () => {
      const enrollRes = await supertest(app.getHttpServer())
        .post('/mfa/enroll')
        .set('Authorization', `Bearer ${userToken}`)
        .set('x-device-id', 'enroll-device-1');
      const { enrollmentId } = enrollRes.body as { enrollmentId: string };

      const confirmRes = await supertest(app.getHttpServer())
        .post('/mfa/enroll/confirm')
        .set('Authorization', `Bearer ${userToken}`)
        .set('x-device-id', 'enroll-device-1')
        .send({ enrollmentId, totpCode: '000000' });

      expect(confirmRes.status).toBe(400);
      expect(confirmRes.body).toMatchObject({ reason: 'invalid_totp' });
    });
  });

  // ── ENROLL-07, ENROLL-10 ───────────────────────────────────────────────────
  describe('DELETE /mfa/admin/enrollment/:userId', () => {
    it('ENROLL-10: returns 403 for non-admin caller', async () => {
      const res = await supertest(app.getHttpServer())
        .delete(`/mfa/admin/enrollment/${TEST_USER}`)
        .set('Authorization', `Bearer ${userToken}`)
        .set('x-device-id', 'enroll-device-1');
      expect(res.status).toBe(403);
    });

    it('ENROLL-07: returns 200 { deleted: false } when no row exists', async () => {
      const res = await supertest(app.getHttpServer())
        .delete(`/mfa/admin/enrollment/${TEST_USER}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .set('x-device-id', 'admin-device');
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ deleted: false });
    });

    it('ENROLL-07: returns 200 { deleted: true } and clears row when present', async () => {
      // Seed a row
      await pool.query(
        `INSERT INTO user_secrets (user_id, totp_secret_encrypted) VALUES ($1, $2)`,
        [TEST_USER, 'placeholder-encrypted-string'],
      );
      const res = await supertest(app.getHttpServer())
        .delete(`/mfa/admin/enrollment/${TEST_USER}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .set('x-device-id', 'admin-device');
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ deleted: true });
      const row = await pool.query(
        `SELECT 1 FROM user_secrets WHERE user_id = $1`,
        [TEST_USER],
      );
      expect(row.rowCount).toBe(0);
    });
  });
});
