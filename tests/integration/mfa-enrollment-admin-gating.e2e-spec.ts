/**
 * Ticket #34 (Phase 11) — DELETE /mfa/admin/enrollment/:userId is gated to `admin`.
 *
 * Codifies items #2 and #3 of the HUMAN-UAT as a live HTTP e2e that boots the real
 * AppModule but overrides the DB token + heavy collaborators, so it runs WITHOUT live
 * Postgres (no DATABASE_URL required, never skips):
 *   - non-admin JWT → 403 from RolesGuard (item #3), repo NOT touched.
 *   - admin JWT → 200 { deleted: true|false }, reaches MfaEnroller.deleteEnrollment (item #2).
 *
 * Mirrors tests/integration/admin-routes.e2e-spec.ts: env-vars-before-imports +
 * Test.createTestingModule({ imports: [AppModule] }).overrideProvider(...).
 */

// Must be set before any NestJS module import to satisfy Joi config validation.
if (!process.env.HASHCASH_HMAC_SECRET) {
  process.env.HASHCASH_HMAC_SECRET = 'a'.repeat(64);
}
if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = 'postgresql://fake:fake@localhost:5432/fake-test-db';
}
if (!process.env.PROXY_SERVICE_REGISTRY) {
  process.env.PROXY_SERVICE_REGISTRY = JSON.stringify({ dummy: 'https://dummy.test:8443' });
}

import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { AppModule } from '../../src/app.module';
import { DB } from '../../src/db/db.port';
import { TrustScoreService } from '../../src/trust-score/trust-score.service';
import { ProxyService } from '../../src/proxy/proxy.service';
import { AuditRepository } from '../../src/audit/audit.repository';
import { createHs256Token } from '../../src/auth/__tests__/test-keys';

const request = require('supertest') as typeof import('supertest');

describe('Ticket #34 — DELETE /mfa/admin/enrollment/:userId admin gating (live e2e)', () => {
  let app: INestApplication;

  // In-memory Db double — only the DELETE the reset path issues is meaningful.
  const deletedUsers: string[] = [];
  const fakeDb = {
    query: jest.fn(async (sql: string, params?: ReadonlyArray<unknown>) => {
      if (/^DELETE FROM user_secrets/i.test(sql.trim())) {
        const userId = (params as [string])[0];
        // Pretend a row exists only for the seeded user, to exercise both branches.
        const existed = userId === 'enrolled-victim';
        if (existed) deletedUsers.push(userId);
        return { rows: [], rowCount: existed ? 1 : 0 };
      }
      return { rows: [], rowCount: 0 };
    }),
    tx: jest.fn(),
  };

  const fakeTrust = {
    evaluateScore: jest.fn().mockResolvedValue(0.1),
    recordTrustContextAfterAllow: jest.fn().mockResolvedValue(undefined),
  };
  const fakeProxy = { forward: jest.fn(), onModuleInit: jest.fn() };
  const fakeAudit = {
    insert: jest.fn().mockResolvedValue(undefined),
    findLogs: jest.fn().mockResolvedValue({ items: [], total: 0 }),
    onModuleDestroy: jest.fn(),
  };

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(DB)
      .useValue(fakeDb)
      .overrideProvider(TrustScoreService)
      .useValue(fakeTrust)
      .overrideProvider(ProxyService)
      .useValue(fakeProxy)
      .overrideProvider(AuditRepository)
      .useValue(fakeAudit)
      .compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
    await app.init();
  });

  afterAll(async () => {
    await app?.close();
  });

  beforeEach(() => {
    fakeDb.query.mockClear();
    fakeProxy.forward.mockClear();
    deletedUsers.length = 0;
  });

  it('ENROLL-10: non-admin JWT is rejected with 403 and never reaches the repository', async () => {
    const token = await createHs256Token(
      { sub: 'regular-user', roles: ['user'] },
      { jti: 'tkt34-nonadmin-403' },
    );
    const res = await request(app.getHttpServer())
      .delete('/mfa/admin/enrollment/enrolled-victim')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(403);
    expect(fakeProxy.forward).not.toHaveBeenCalled();
    const deleteCalls = fakeDb.query.mock.calls.filter(([sql]) =>
      /^DELETE FROM user_secrets/i.test(String(sql).trim()),
    );
    expect(deleteCalls).toHaveLength(0);
  });

  it('ENROLL-09: missing Authorization header → 401 (auth before RBAC)', async () => {
    const res = await request(app.getHttpServer()).delete('/mfa/admin/enrollment/enrolled-victim');
    expect(res.status).toBe(401);
  });

  it('ENROLL-07: admin JWT returns 200 { deleted: true } when a row existed', async () => {
    const token = await createHs256Token(
      { sub: 'admin-1', roles: ['admin'] },
      { jti: 'tkt34-admin-deleted-true' },
    );
    const res = await request(app.getHttpServer())
      .delete('/mfa/admin/enrollment/enrolled-victim')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ deleted: true });
    expect(deletedUsers).toContain('enrolled-victim');
  });

  it('ENROLL-07: admin JWT returns 200 { deleted: false } when no row existed', async () => {
    const token = await createHs256Token(
      { sub: 'admin-1', roles: ['admin'] },
      { jti: 'tkt34-admin-deleted-false' },
    );
    const res = await request(app.getHttpServer())
      .delete('/mfa/admin/enrollment/never-enrolled')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ deleted: false });
  });
});
