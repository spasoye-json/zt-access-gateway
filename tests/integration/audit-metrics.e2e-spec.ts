/**
 * Phase 9 — Audit + Metrics integration e2e (09-03).
 *
 * Boots the real AppModule with:
 *   - AuditRepository mocked (avoids live DB)
 *   - TrustScoreService mocked (avoids live DB)
 *
 * Exercises:
 *   - GET /metrics  →  200 text/plain; all 4 registry metric names present (MTRC-03, MTRC-04)
 *   - GET /audit/logs  →  401 no auth, 403 non-admin, 200 admin, 400 limit>200 (AUDT-05)
 *
 * Env vars set before imports — ConfigModule.forRoot() validates at decoration time.
 */

// Must be set before any NestJS module import to satisfy Joi config validation.
if (!process.env.HASHCASH_HMAC_SECRET) {
  process.env.HASHCASH_HMAC_SECRET = 'a'.repeat(64);
}
if (!process.env.DATABASE_URL) {
  // Fake URL — pg Pool is lazy; no actual connection is made during this test suite.
  process.env.DATABASE_URL = 'postgresql://fake:fake@localhost:5432/fake-test-db';
}
if (!process.env.PROXY_SERVICE_REGISTRY) {
  process.env.PROXY_SERVICE_REGISTRY = JSON.stringify({ dummy: 'https://dummy.test:8443' });
}

import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '../../src/app.module';
import { AuditRepository } from '../../src/audit/audit.repository';
import { TrustScoreService } from '../../src/trust-score/trust-score.service';
import { createHs256Token } from '../../src/auth/__tests__/test-keys';
import type { AuditLog } from '../../src/audit/audit-log.interface';

describe('Phase 9 — Audit + Metrics e2e', () => {
  let app: INestApplication;

  const fakeAudit = {
    insert: jest.fn(),
    findLogs: jest.fn(),
    onModuleDestroy: jest.fn(),
  };

  const fakeTrustScore = {
    evaluateScore: jest.fn().mockResolvedValue(0.1),
    recordTrustContextAfterAllow: jest.fn(),
  };

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(AuditRepository)
      .useValue(fakeAudit)
      .overrideProvider(TrustScoreService)
      .useValue(fakeTrustScore)
      .compile();

    app = moduleRef.createNestApplication();
    // Mirror production ValidationPipe (see src/bootstrap-app.ts).
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
    await app.init();
  });

  afterAll(async () => {
    await app?.close();
  });

  describe('GET /metrics (MTRC-03, MTRC-04)', () => {
    it('returns 200 with prom-client text/plain content-type (order-agnostic, MTRC-03)', async () => {
      const res = await request(app.getHttpServer()).get('/metrics');
      expect(res.status).toBe(200);
      // Phase 13 SC-3 — D-11: split-and-assert to accept both prom-client
      // orderings (`text/plain; version=...; charset=...` and
      // `text/plain; charset=...; version=...`). Order-agnostic by construction.
      const ct = res.headers['content-type'];
      expect(ct).toContain('text/plain');
      expect(ct).toMatch(/version=0\.0\.4/);
      expect(ct).toMatch(/charset=utf-8/);
    });

    it('body contains metric names from all 4 registries (MTRC-04)', async () => {
      // prom-client emits # HELP / # TYPE lines even for zero-value counters;
      // no need to seed a honeypot hit (which tarpits 2-5 s).
      const res = await request(app.getHttpServer()).get('/metrics');
      // Honeypot registry (Phase 2 — SecurityMetricsService)
      expect(res.text).toContain('zt_gateway_honeypot_triggers_total');
      // Gateway cross-cutting registry (MetricsService own registry — MTRC-01, MTRC-02)
      expect(res.text).toMatch(/zt_gateway_requests_total|# HELP zt_gateway_requests_total/);
      expect(res.text).toMatch(
        /zt_gateway_stage_duration_seconds|# HELP zt_gateway_stage_duration_seconds/,
      );
      expect(res.text).toMatch(
        /zt_gateway_audit_wal_duration_seconds|# HELP zt_gateway_audit_wal_duration_seconds/,
      );
    });
  });

  describe('GET /audit/logs (AUDT-05)', () => {
    beforeEach(() => {
      fakeAudit.findLogs.mockReset();
      fakeAudit.findLogs.mockResolvedValue({
        items: [
          {
            id: 1,
            userId: 'admin-1',
            resource: '/x',
            action: 'GET',
            decision: 'allow',
            trustScore: 0.1,
            ja4hFingerprint: null,
            ipAddress: null,
            userAgent: null,
            requestId: null,
            eventType: null,
            createdAt: new Date(),
          } satisfies AuditLog,
        ],
        total: 1,
      });
    });

    it('returns 401 with no Authorization header', async () => {
      const res = await request(app.getHttpServer()).get('/audit/logs');
      expect(res.status).toBe(401);
    });

    it('returns 403 for non-admin JWT (RolesGuard)', async () => {
      const token = await createHs256Token(
        { sub: 'u1', roles: ['user'] },
        { jti: 'audit-e2e-nonadmin' },
      );
      const res = await request(app.getHttpServer())
        .get('/audit/logs')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(403);
    });

    it('returns 200 with { items, total } for admin JWT', async () => {
      const token = await createHs256Token(
        { sub: 'admin-1', roles: ['admin'] },
        { jti: 'audit-e2e-admin-200' },
      );
      const res = await request(app.getHttpServer())
        .get('/audit/logs')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('items');
      expect(res.body).toHaveProperty('total', 1);
      expect(Array.isArray(res.body.items)).toBe(true);
      expect(fakeAudit.findLogs).toHaveBeenCalled();
    });

    it('returns 400 when limit > 200 (AuditLogsQueryDto @Max(200))', async () => {
      const token = await createHs256Token(
        { sub: 'admin-1', roles: ['admin'] },
        { jti: 'audit-e2e-admin-400' },
      );
      const res = await request(app.getHttpServer())
        .get('/audit/logs?limit=999')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(400);
    });
  });
});
