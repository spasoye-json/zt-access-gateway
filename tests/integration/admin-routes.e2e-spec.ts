/**
 * Phase 12 — Admin route allowlist closure (live e2e).
 *
 * Replaces tests/integration/policy.e2e-spec.ts (deleted in a367954, "superseded
 * by plan 10-06 e2e" — but the gateway.e2e-spec.ts written by plan 10-06 does
 * NOT cover /policy/admin/* or /audit/logs admin RBAC. This spec closes that
 * gap by booting the real AppModule with the plan 12-01 GatewayMiddleware fix
 * applied and asserting all five Phase 12 success criteria end-to-end.
 *
 * Mirrors tests/integration/audit-metrics.e2e-spec.ts:
 *   - env-vars-before-imports (Joi config validation runs at module decoration)
 *   - Test.createTestingModule({ imports: [AppModule] }).overrideProvider(...)
 *   - createHs256Token from src/auth/__tests__/test-keys.ts with unique jti per test
 *
 * Run: npx jest --config tests/jest-e2e.json tests/integration/admin-routes.e2e-spec.ts
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
import * as request from 'supertest';
import { AppModule } from '../../src/app.module';
import { AuditRepository } from '../../src/audit/audit.repository';
import { TrustScoreService } from '../../src/trust-score/trust-score.service';
import { PolicyEvaluatorService } from '../../src/policy/policy-evaluator.service';
import { ThreatEscalationService } from '../../src/policy/threat-escalation.service';
import { ProxyService } from '../../src/proxy/proxy.service';
import { createHs256Token } from '../../src/auth/__tests__/test-keys';
import { AuthService } from '../../src/auth/auth.service';

describe('Phase 12 — Admin route allowlist closure (live e2e)', () => {
  let app: INestApplication;
  let validateTokenSpy: jest.SpyInstance;

  const fakeAudit = {
    insert: jest.fn().mockResolvedValue(undefined),
    findLogs: jest.fn().mockResolvedValue({ items: [], total: 0 }),
    onModuleDestroy: jest.fn(),
  };

  const fakeTrust = {
    evaluateScore: jest.fn().mockResolvedValue(0.1),
    recordTrustContextAfterAllow: jest.fn().mockResolvedValue(undefined),
  };

  const fakePolicy = {
    addRule: jest.fn().mockResolvedValue(true),
    removeRule: jest.fn().mockResolvedValue(true),
    getRules: jest.fn().mockResolvedValue([]),
    evaluate: jest.fn(),
    onModuleInit: jest.fn(),
  };

  const fakeThreat = {
    snapshot: jest.fn().mockReturnValue({ level: 'Normal' }),
    setManualLevel: jest.fn(),
    clearManualLevel: jest.fn(),
  };

  const fakeProxy = {
    forward: jest.fn(),
    onModuleInit: jest.fn(),
  };

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(AuditRepository).useValue(fakeAudit)
      .overrideProvider(TrustScoreService).useValue(fakeTrust)
      .overrideProvider(PolicyEvaluatorService).useValue(fakePolicy)
      .overrideProvider(ThreatEscalationService).useValue(fakeThreat)
      .overrideProvider(ProxyService).useValue(fakeProxy)
      .compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
    app.enableCors({ origin: '*' });    // mirror src/main.ts:36 so OPTIONS preflight returns CORS headers
    await app.init();

    const realAuth = moduleRef.get(AuthService);
    validateTokenSpy = jest.spyOn(realAuth, 'validateToken');
  });

  afterAll(async () => {
    await app?.close();
  });

  beforeEach(() => {
    fakeAudit.findLogs.mockClear();
    fakeProxy.forward.mockClear();
    fakePolicy.addRule.mockClear();
    fakePolicy.removeRule.mockClear();
    fakePolicy.getRules.mockClear();
    fakeThreat.snapshot.mockClear();
    fakeThreat.setManualLevel.mockClear();
    fakeThreat.clearManualLevel.mockClear();
    validateTokenSpy.mockClear();
  });

  // ── Success criterion 1: GET /audit/logs (AUDT-05) ──────────────────────
  describe('GET /audit/logs (AUDT-05)', () => {
    it('admin JWT returns 200 through gateway and reaches AuditController (NOT proxy fallback)', async () => {
      const token = await createHs256Token(
        { sub: 'admin-1', roles: ['admin'] },
        { jti: 'p12-audit-200' },
      );
      const res = await request(app.getHttpServer())
        .get('/audit/logs')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('items');
      expect(res.body).toHaveProperty('total');
      expect(fakeAudit.findLogs).toHaveBeenCalled();
      expect(fakeProxy.forward).not.toHaveBeenCalled();
    });
  });

  // ── Success criterion 2: /policy/admin/rules (PLCY-06) ─────────────────
  describe('/policy/admin/rules (PLCY-06)', () => {
    it('GET admin returns 200 and reaches PolicyEvaluatorService.getRules', async () => {
      const token = await createHs256Token(
        { sub: 'admin-1', roles: ['admin'] },
        { jti: 'p12-pol-rules-get' },
      );
      const res = await request(app.getHttpServer())
        .get('/policy/admin/rules')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ rules: [] });
      expect(fakePolicy.getRules).toHaveBeenCalled();
      expect(fakeProxy.forward).not.toHaveBeenCalled();
    });

    it('POST admin returns 200 with { added: true } and forwards DTO to addRule', async () => {
      const token = await createHs256Token(
        { sub: 'admin-1', roles: ['admin'] },
        { jti: 'p12-pol-rules-post' },
      );
      const res = await request(app.getHttpServer())
        .post('/policy/admin/rules')
        .set('Authorization', `Bearer ${token}`)
        .send({ sub: 'role:user', obj: '/api/x', act: 'GET' });
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ added: true });
      expect(fakePolicy.addRule).toHaveBeenCalledWith('role:user', '/api/x', 'GET');
      expect(fakeProxy.forward).not.toHaveBeenCalled();
    });

    it('DELETE admin returns 200 with { removed: true }', async () => {
      const token = await createHs256Token(
        { sub: 'admin-1', roles: ['admin'] },
        { jti: 'p12-pol-rules-del' },
      );
      const res = await request(app.getHttpServer())
        .delete('/policy/admin/rules')
        .set('Authorization', `Bearer ${token}`)
        .send({ sub: 'role:user', obj: '/api/x', act: 'GET' });
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ removed: true });
      expect(fakePolicy.removeRule).toHaveBeenCalled();
      expect(fakeProxy.forward).not.toHaveBeenCalled();
    });
  });

  // ── Success criterion 2: /policy/admin/escalation (PLCY-11) ────────────
  describe('/policy/admin/escalation (PLCY-11)', () => {
    it('POST admin returns 200 and reaches ThreatEscalationService.setManualLevel', async () => {
      const token = await createHs256Token(
        { sub: 'admin-1', roles: ['admin'] },
        { jti: 'p12-esc-set' },
      );
      // EscalationLevelDto @IsIn(['Normal','Elevated','Critical']) — Title case required.
      const res = await request(app.getHttpServer())
        .post('/policy/admin/escalation')
        .set('Authorization', `Bearer ${token}`)
        .send({ level: 'Elevated' });
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ ok: true, level: 'Elevated' });
      expect(fakeThreat.setManualLevel).toHaveBeenCalledWith('Elevated');
      expect(fakeProxy.forward).not.toHaveBeenCalled();
    });

    it('DELETE admin returns 200 and reaches ThreatEscalationService.clearManualLevel', async () => {
      const token = await createHs256Token(
        { sub: 'admin-1', roles: ['admin'] },
        { jti: 'p12-esc-del' },
      );
      const res = await request(app.getHttpServer())
        .delete('/policy/admin/escalation')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ ok: true });
      expect(fakeThreat.clearManualLevel).toHaveBeenCalled();
      expect(fakeProxy.forward).not.toHaveBeenCalled();
    });
  });

  // ── Success criterion 3: non-admin → 403 from RolesGuard, NOT 404 ──────
  describe('Non-admin RBAC (success criterion 3)', () => {
    it('GET /audit/logs with non-admin JWT returns 403 (NOT 404 from proxy fallback)', async () => {
      const token = await createHs256Token(
        { sub: 'u1', roles: ['user'] },
        { jti: 'p12-audit-403' },
      );
      const res = await request(app.getHttpServer())
        .get('/audit/logs')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(403);
      expect(fakeProxy.forward).not.toHaveBeenCalled();
      expect(fakeAudit.findLogs).not.toHaveBeenCalled();
    });

    it('POST /policy/admin/rules with non-admin JWT returns 403', async () => {
      const token = await createHs256Token(
        { sub: 'u1', roles: ['user'] },
        { jti: 'p12-pol-403' },
      );
      const res = await request(app.getHttpServer())
        .post('/policy/admin/rules')
        .set('Authorization', `Bearer ${token}`)
        .send({ sub: 'role:user', obj: '/api/x', act: 'GET' });
      expect(res.status).toBe(403);
      expect(fakeProxy.forward).not.toHaveBeenCalled();
      expect(fakePolicy.addRule).not.toHaveBeenCalled();
    });

    it('POST /policy/admin/escalation with non-admin JWT returns 403', async () => {
      const token = await createHs256Token(
        { sub: 'u1', roles: ['user'] },
        { jti: 'p12-esc-403' },
      );
      const res = await request(app.getHttpServer())
        .post('/policy/admin/escalation')
        .set('Authorization', `Bearer ${token}`)
        .send({ level: 'Elevated' });
      expect(res.status).toBe(403);
      expect(fakeProxy.forward).not.toHaveBeenCalled();
      expect(fakeThreat.setManualLevel).not.toHaveBeenCalled();
    });
  });

  // ── Success criterion 4: OPTIONS preflight bypasses auth ───────────────
  describe('OPTIONS preflight (success criterion 4, F-p)', () => {
    it('OPTIONS /audit/logs returns 2xx with access-control-allow-origin header', async () => {
      const res = await request(app.getHttpServer())
        .options('/audit/logs')
        .set('Origin', 'https://example.test')
        .set('Access-Control-Request-Method', 'GET')
        .set('Access-Control-Request-Headers', 'authorization');
      expect(res.status).toBeGreaterThanOrEqual(200);
      expect(res.status).toBeLessThan(300);
      expect(res.headers['access-control-allow-origin']).toBeDefined();
      expect(fakeProxy.forward).not.toHaveBeenCalled();
      expect(fakeAudit.findLogs).not.toHaveBeenCalled();
    });

    it('OPTIONS /policy/admin/rules returns 2xx with access-control-allow-origin header', async () => {
      const res = await request(app.getHttpServer())
        .options('/policy/admin/rules')
        .set('Origin', 'https://example.test')
        .set('Access-Control-Request-Method', 'POST');
      expect(res.status).toBeGreaterThanOrEqual(200);
      expect(res.status).toBeLessThan(300);
      expect(res.headers['access-control-allow-origin']).toBeDefined();
      expect(fakeProxy.forward).not.toHaveBeenCalled();
      expect(fakePolicy.addRule).not.toHaveBeenCalled();
    });
  });

  // ── Phase 13 SC-2 — JwtAuthGuard double-validation closure ───────────────
  describe('Phase 13 SC-2 — validateToken called exactly once per request (D-08)', () => {
    it('GET /policy/admin/rules with admin JWT — AuthService.validateToken called EXACTLY ONCE', async () => {
      const token = await createHs256Token(
        { sub: 'admin-1', roles: ['admin'] },
        { jti: 'p13-sc2-pol-rules' },
      );
      const res = await request(app.getHttpServer())
        .get('/policy/admin/rules')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(validateTokenSpy).toHaveBeenCalledTimes(1);
    });

    it('POST /auth/revoke with admin JWT — AuthService.validateToken called EXACTLY ONCE', async () => {
      const token = await createHs256Token(
        { sub: 'admin-1', roles: ['admin'] },
        { jti: 'p13-sc2-auth-revoke' },
      );
      const res = await request(app.getHttpServer())
        .post('/auth/revoke')
        .set('Authorization', `Bearer ${token}`)
        .send({
          jti: 'some-other-jti-to-revoke',
          exp: Math.floor(Date.now() / 1000) + 3600,
        });

      // /auth/revoke may return 200, 201, or 204 depending on controller wiring;
      // what matters for SC-2 is the call count, not the body.
      expect([200, 201, 204]).toContain(res.status);
      expect(validateTokenSpy).toHaveBeenCalledTimes(1);
    });

    it('regression — spy count is not silently 0 (would indicate @UseGuards bypass)', async () => {
      const token = await createHs256Token(
        { sub: 'admin-1', roles: ['admin'] },
        { jti: 'p13-sc2-not-zero' },
      );
      await request(app.getHttpServer())
        .get('/policy/admin/rules')
        .set('Authorization', `Bearer ${token}`);

      expect(validateTokenSpy.mock.calls.length).toBeGreaterThan(0);
      expect(validateTokenSpy.mock.calls.length).toBe(1);
    });
  });
});
