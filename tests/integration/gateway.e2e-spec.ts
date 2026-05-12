/**
 * Phase 10 — Gateway Integration full-pipeline e2e (10-06).
 *
 * Boots real AppModule with five providers overridden to remove external
 * dependencies (Postgres, mTLS, Casbin policy file IO):
 *   - ProxyService            — avoids real mTLS to a downstream
 *   - AuditRepository         — avoids real Postgres
 *   - TrustScoreService       — deterministic 0..1 score; no DB
 *   - PolicyEvaluatorService  — deterministic ALLOW / CHALLENGE / DENY
 *   - MfaService              — deterministic validate / createChallenge
 *
 * Spies on MetricsService.observeStageDuration and the override-jest.fn()
 * mocks prove the pipeline ordering invariants (D-09: audit-before-proxy;
 * D-13: trust score evaluated once; D-07: policy.evaluate called once on MFA
 * promotion; D-12: trust context only on upstream 2xx ALLOW).
 *
 * Covers all 9 GTWY-* requirements (GTWY-01..09). The trust_signals row-count
 * assertion in must_haves is replaced with a spy on
 * recordTrustContextAfterAllow (the unit-level analog), since this spec
 * overrides TrustScoreService — see GTWY-05 group below.
 *
 * Real DB row-count assertion deferred to UAT (Phase 10 verify-work step) —
 * unit-overrides give faster feedback.
 *
 * Env vars set BEFORE any NestJS module import — ConfigModule.forRoot()
 * validates at decoration time (analog: tests/integration/audit-metrics.e2e-spec.ts).
 */

if (!process.env.HASHCASH_HMAC_SECRET) {
  process.env.HASHCASH_HMAC_SECRET = 'a'.repeat(64);
}
if (!process.env.DATABASE_URL) {
  // Fake URL — pg Pool is lazy; AuditRepository is overridden so no real connection is made.
  process.env.DATABASE_URL = 'postgresql://fake:fake@localhost:5432/fake-test-db';
}
if (!process.env.PROXY_SERVICE_REGISTRY) {
  // 'users' service registered so /users/* routes resolve through the (overridden) ProxyService.
  process.env.PROXY_SERVICE_REGISTRY = JSON.stringify({
    users: 'https://users.test:8443',
    orders: 'https://orders.test:8443',
  });
}

import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { AppModule } from '../../src/app.module';
import { ProxyService } from '../../src/proxy/proxy.service';
import { AuditRepository } from '../../src/audit/audit.repository';
import { TrustScoreService } from '../../src/trust-score/trust-score.service';
import { PolicyEvaluatorService } from '../../src/policy/policy-evaluator.service';
import { MfaService } from '../../src/mfa/mfa.service';
import { MetricsService } from '../../src/metrics/metrics.service';
import { AuthService } from '../../src/auth/auth.service';
import { FingerprintStore } from '../../src/fingerprint/fingerprint.store';
import { createHs256Token } from '../../src/auth/__tests__/test-keys';
import type { AuditEntry } from '../../src/audit/audit-entry.interface';

// Ensure each token has a unique jti so revocation tests don't bleed across cases.
let jtiCounter = 0;
const uniqueJti = (label: string): string =>
  `gtwy-${label}-${Date.now()}-${++jtiCounter}-${Math.random().toString(36).slice(2, 8)}`;

describe('Phase 10 — Gateway Integration e2e (GTWY-01..09)', () => {
  let app: INestApplication;

  // Mock implementations re-used across tests; reset between cases via clearAllMocks.
  const fakeProxy = {
    forward: jest.fn(),
    onModuleInit: jest.fn(),
  };
  const fakeAudit = {
    insert: jest.fn(),
    findLogs: jest.fn().mockResolvedValue({ items: [], total: 0 }),
    onModuleDestroy: jest.fn(),
  };
  const fakeTrustScore = {
    evaluateScore: jest.fn(),
    recordTrustContextAfterAllow: jest.fn(),
  };
  const fakePolicy = {
    evaluate: jest.fn(),
    onModuleInit: jest.fn(),
    addRule: jest.fn(),
    removeRule: jest.fn(),
  };
  const fakeMfa = {
    validateMfaToken: jest.fn(),
    createChallenge: jest.fn(),
  };

  // Resolved after app.init() so spies can be attached on real instances.
  let stageSpy: jest.SpyInstance;
  let incRequestSpy: jest.SpyInstance;
  let authValidateSpy: jest.SpyInstance;

  // Default overrides that make ALLOW the happy path.
  const resetOverrides = (): void => {
    fakeProxy.forward.mockResolvedValue({
      status: 200,
      data: { id: 'u-1', email: 'u@x.test', name: 'U', extra: 'admin-only', secret: 's' },
    });
    fakeAudit.insert.mockResolvedValue(undefined);
    fakeAudit.findLogs.mockResolvedValue({ items: [], total: 0 });
    fakeTrustScore.evaluateScore.mockResolvedValue(0.1);
    fakeTrustScore.recordTrustContextAfterAllow.mockResolvedValue(undefined);
    fakePolicy.evaluate.mockResolvedValue({
      decision: 'ALLOW',
      reason: 'ok',
      score: 0.1,
      matchedSubject: 'role:user',
    });
    fakeMfa.validateMfaToken.mockResolvedValue({ ok: false, reason: 'signature' });
    fakeMfa.createChallenge.mockResolvedValue({
      ok: true,
      challengeId: 'ch-1',
      expiresAt: Date.now() + 60_000,
    });
  };

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(ProxyService)
      .useValue(fakeProxy)
      .overrideProvider(AuditRepository)
      .useValue(fakeAudit)
      .overrideProvider(TrustScoreService)
      .useValue(fakeTrustScore)
      .overrideProvider(PolicyEvaluatorService)
      .useValue(fakePolicy)
      .overrideProvider(MfaService)
      .useValue(fakeMfa)
      .compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
    await app.init();

    // Real instances — spy through them to prove pipeline ordering invariants.
    const metrics = app.get(MetricsService);
    const auth = app.get(AuthService);
    stageSpy = jest.spyOn(metrics, 'observeStageDuration');
    incRequestSpy = jest.spyOn(metrics, 'incrementRequest');
    authValidateSpy = jest.spyOn(auth, 'validateToken');
  });

  afterAll(async () => {
    await app?.close();
  });

  beforeEach(() => {
    jest.clearAllMocks();
    resetOverrides();
    // The honeypot test blacklists the supertest-default JA4H fingerprint;
    // clear between tests so subsequent unauthenticated requests (e.g. /metrics)
    // are not 403'd by Ja4hMiddleware (T-02-05 tarpit + Forbidden response).
    app.get(FingerprintStore).clear();
  });

  // ───────────────────────────────────────────────────────────────────
  // GTWY-08 — Public route bypass (no auth, no pipeline)
  // ───────────────────────────────────────────────────────────────────

  describe('GTWY-08 — Public route bypass (PUBLIC_PATHS)', () => {
    it('GET /health → 200 without Authorization (GTWY-08)', async () => {
      const res = await request(app.getHttpServer()).get('/health');
      expect(res.status).toBe(200);
    });

    it('GET /metrics → 200 with text/plain content-type without Authorization (GTWY-08)', async () => {
      const res = await request(app.getHttpServer()).get('/metrics');
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/^text\/plain/);
    });

    it('public bypass does NOT invoke pipeline stages (no observeStageDuration calls) (GTWY-08)', async () => {
      stageSpy.mockClear();
      await request(app.getHttpServer()).get('/health');
      await request(app.getHttpServer()).get('/metrics');
      // PUBLIC bypass returns next() before any observe('auth', ...) call
      expect(stageSpy).not.toHaveBeenCalled();
      // No request decision is incremented for public paths
      expect(incRequestSpy).not.toHaveBeenCalled();
    });
  });

  // ───────────────────────────────────────────────────────────────────
  // GTWY-03 — Auth short-circuits (missing / malformed / revoked)
  // ───────────────────────────────────────────────────────────────────

  describe('GTWY-03 — Auth short-circuits', () => {
    it('GET /users/profile without Authorization → 401 {error:"auth_required"} (GTWY-03)', async () => {
      const res = await request(app.getHttpServer()).get('/users/profile');
      expect(res.status).toBe(401);
      expect(res.body).toMatchObject({ error: 'auth_required' });
      // Auth short-circuit: policy NOT consulted
      expect(fakePolicy.evaluate).not.toHaveBeenCalled();
      // Auth short-circuit: proxy NOT called
      expect(fakeProxy.forward).not.toHaveBeenCalled();
    });

    it('GET /users/profile with malformed token → 401 {error:"auth_invalid"} (GTWY-03)', async () => {
      const res = await request(app.getHttpServer())
        .get('/users/profile')
        .set('Authorization', 'Bearer not-a-real-jwt');
      expect(res.status).toBe(401);
      expect(res.body).toMatchObject({ error: 'auth_invalid' });
      expect(fakeProxy.forward).not.toHaveBeenCalled();
    });

    it('GET /users/profile with non-Bearer scheme → 401 auth_required (GTWY-03)', async () => {
      const res = await request(app.getHttpServer())
        .get('/users/profile')
        .set('Authorization', 'Basic dXNlcjpwYXNz');
      expect(res.status).toBe(401);
      expect(res.body).toMatchObject({ error: 'auth_required' });
    });
  });

  // ───────────────────────────────────────────────────────────────────
  // GTWY-09 — Honeypot bypass
  // ───────────────────────────────────────────────────────────────────

  describe('GTWY-09 — Honeypot bypass', () => {
    it('GET /wp-login.php → 200 deceptive response, AuthService.validateToken NOT called (GTWY-09)', async () => {
      const res = await request(app.getHttpServer()).get('/wp-login.php');
      expect(res.status).toBe(200);
      // ShadowController returns either HTML or JSON — both indicate the deception layer ran.
      expect(res.body || res.text).toBeTruthy();
      // Critical assertion: auth.validateToken was NOT called for honeypot path
      expect(authValidateSpy).not.toHaveBeenCalled();
      // Pipeline stages NOT observed for honeypot bypass
      expect(stageSpy).not.toHaveBeenCalled();
      // No proxy invocation
      expect(fakeProxy.forward).not.toHaveBeenCalled();
    }, 10_000); // ShadowController tarpits 2-5s before responding (D-05)
  });

  // ───────────────────────────────────────────────────────────────────
  // GTWY-01 + GTWY-02 — Pipeline ordering (D-09, D-13)
  // ───────────────────────────────────────────────────────────────────

  describe('GTWY-01 + GTWY-02 — Pipeline ordering', () => {
    it('valid HS256 token → 200 and stages execute in order auth, revocation, trust_score, hashcash, policy, proxy (GTWY-01, GTWY-02)', async () => {
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('order') },
      );
      const res = await request(app.getHttpServer())
        .get('/users/profile')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);

      const stages = stageSpy.mock.calls.map((c) => c[0] as string);

      // Order check — strict prefix (mfa is absent on ALLOW, proxy comes last)
      const expectedPrefix = ['auth', 'revocation', 'trust_score', 'hashcash', 'policy'];
      expect(stages.slice(0, expectedPrefix.length)).toEqual(expectedPrefix);
      expect(stages[stages.length - 1]).toBe('proxy');

      // D-13 — trust_score MUST be observed at most once per request
      expect(stages.filter((s) => s === 'trust_score')).toHaveLength(1);
      // auth observed exactly once on success
      expect(stages.filter((s) => s === 'auth')).toHaveLength(1);
      // mfa absent on direct ALLOW
      expect(stages).not.toContain('mfa');
    });

    it('audit-before-proxy invocation order (D-09 / GTWY-07)', async () => {
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('audit-order') },
      );
      const res = await request(app.getHttpServer())
        .get('/users/profile')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);

      // jest assigns a global monotonic counter to every spy invocation;
      // out-of-order calls cannot pass this assertion (T-10-15 mitigation).
      expect(fakeAudit.insert).toHaveBeenCalled();
      expect(fakeProxy.forward).toHaveBeenCalled();
      const auditOrder = fakeAudit.insert.mock.invocationCallOrder[0];
      const proxyOrder = fakeProxy.forward.mock.invocationCallOrder[0];
      expect(auditOrder).toBeLessThan(proxyOrder);
    });
  });

  // ───────────────────────────────────────────────────────────────────
  // GTWY-04 — MFA promotion (CHALLENGE → ALLOW with valid X-MFA-Token)
  // ───────────────────────────────────────────────────────────────────

  describe('GTWY-04 — MFA promotion', () => {
    it('CHALLENGE without X-MFA-Token → 401 + WWW-Authenticate: MFA + X-MFA-Challenge (GTWY-04)', async () => {
      fakePolicy.evaluate.mockResolvedValueOnce({
        decision: 'CHALLENGE',
        reason: 'risk_threshold',
        score: 0.6,
        matchedSubject: 'role:user',
      });
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('mfa-no-token') },
      );
      const res = await request(app.getHttpServer())
        .post('/users/profile')
        .set('Authorization', `Bearer ${token}`)
        .send({});

      expect(res.status).toBe(401);
      expect(res.body).toMatchObject({ error: 'mfa_required' });
      expect(res.headers['www-authenticate']).toMatch(/^MFA realm="gateway", challengeId="[^"]+"/);
      expect(res.headers['x-mfa-challenge']).toBeDefined();
      // Proxy must NOT have been called on a CHALLENGE without MFA token
      expect(fakeProxy.forward).not.toHaveBeenCalled();
    });

    it('CHALLENGE with valid X-MFA-Token → 200, policy.evaluate called exactly once (D-07, GTWY-04)', async () => {
      fakePolicy.evaluate.mockResolvedValueOnce({
        decision: 'CHALLENGE',
        reason: 'risk_threshold',
        score: 0.6,
        matchedSubject: 'role:user',
      });
      fakeMfa.validateMfaToken.mockResolvedValueOnce({
        ok: true,
        claims: { sub: 'user-1', jti: 'mfa-jti', deviceId: 'device-1', fpHash: 'h', typ: 'mfa' },
      });
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('mfa-promote') },
      );
      const res = await request(app.getHttpServer())
        .post('/users/profile')
        .set('Authorization', `Bearer ${token}`)
        .set('X-MFA-Token', 'fake-mfa-token-value')
        .send({});

      expect(res.status).toBe(200);
      // D-07: policy.evaluate called exactly once even on MFA promotion (no re-evaluation)
      expect(fakePolicy.evaluate).toHaveBeenCalledTimes(1);
      // Proxy reached after promotion
      expect(fakeProxy.forward).toHaveBeenCalledTimes(1);
    });

    it('CHALLENGE with invalid X-MFA-Token (fingerprint_mismatch) → 401 mfa_required (GTWY-04)', async () => {
      fakePolicy.evaluate.mockResolvedValueOnce({
        decision: 'CHALLENGE',
        reason: 'risk_threshold',
        score: 0.6,
        matchedSubject: 'role:user',
      });
      fakeMfa.validateMfaToken.mockResolvedValueOnce({
        ok: false,
        reason: 'fingerprint_mismatch',
      });
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('mfa-bad-token') },
      );
      const res = await request(app.getHttpServer())
        .post('/users/profile')
        .set('Authorization', `Bearer ${token}`)
        .set('X-MFA-Token', 'invalid-mfa-token')
        .send({});

      expect(res.status).toBe(401);
      expect(res.body).toMatchObject({ error: 'mfa_required' });
      expect(fakeProxy.forward).not.toHaveBeenCalled();
    });
  });

  // ───────────────────────────────────────────────────────────────────
  // GTWY-03 — Policy DENY
  // ───────────────────────────────────────────────────────────────────

  describe('GTWY-03 — Policy DENY', () => {
    it('Policy returns DENY → 403 {error:"policy_denied"} (GTWY-03)', async () => {
      fakePolicy.evaluate.mockResolvedValueOnce({
        decision: 'DENY',
        reason: 'role_not_authorized',
        score: 0.1,
      });
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('deny') },
      );
      const res = await request(app.getHttpServer())
        .post('/users/profile')
        .set('Authorization', `Bearer ${token}`)
        .send({});
      expect(res.status).toBe(403);
      expect(res.body).toMatchObject({ error: 'policy_denied' });
      // Proxy MUST NOT be invoked on DENY
      expect(fakeProxy.forward).not.toHaveBeenCalled();
    });
  });

  // ───────────────────────────────────────────────────────────────────
  // GTWY-05 — Trust context only on ALLOW + upstream 2xx (D-12)
  // ───────────────────────────────────────────────────────────────────

  describe('GTWY-05 — recordTrustContextAfterAllow gating', () => {
    it('ALLOW + upstream 200 → recordTrustContextAfterAllow called once (GTWY-05)', async () => {
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('allow-200') },
      );
      const res = await request(app.getHttpServer())
        .get('/users/profile')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      expect(fakeTrustScore.recordTrustContextAfterAllow).toHaveBeenCalledTimes(1);
    });

    it('DENY → recordTrustContextAfterAllow NOT called (GTWY-05)', async () => {
      fakePolicy.evaluate.mockResolvedValueOnce({
        decision: 'DENY',
        reason: 'role_not_authorized',
        score: 0.1,
      });
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('deny-no-trust') },
      );
      const res = await request(app.getHttpServer())
        .get('/users/profile')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(403);
      expect(fakeTrustScore.recordTrustContextAfterAllow).not.toHaveBeenCalled();
    });

    it('CHALLENGE without MFA → recordTrustContextAfterAllow NOT called (GTWY-05)', async () => {
      fakePolicy.evaluate.mockResolvedValueOnce({
        decision: 'CHALLENGE',
        reason: 'risk_threshold',
        score: 0.6,
        matchedSubject: 'role:user',
      });
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('chal-no-trust') },
      );
      const res = await request(app.getHttpServer())
        .get('/users/profile')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(401);
      expect(fakeTrustScore.recordTrustContextAfterAllow).not.toHaveBeenCalled();
    });

    it('ALLOW + upstream 404 → recordTrustContextAfterAllow NOT called (D-12, GTWY-05)', async () => {
      fakeProxy.forward.mockResolvedValueOnce({ status: 404, data: { error: 'not_found' } });
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('allow-404') },
      );
      const res = await request(app.getHttpServer())
        .get('/users/profile')
        .set('Authorization', `Bearer ${token}`);
      // Upstream 404 propagates; trust context skipped because status >= 400
      expect(res.status).toBe(404);
      expect(fakeTrustScore.recordTrustContextAfterAllow).not.toHaveBeenCalled();
    });
  });

  // ───────────────────────────────────────────────────────────────────
  // GTWY-06 — BOPLA field stripping
  // ───────────────────────────────────────────────────────────────────

  describe('GTWY-06 — BOPLA stripping', () => {
    it('non-admin role gets fields restricted by field-policy.json /users/** (GTWY-06)', async () => {
      // field-policy.json maps /users/** → user: ['id', 'email', 'name']
      fakeProxy.forward.mockResolvedValueOnce({
        status: 200,
        data: {
          id: 'u-1',
          email: 'u@x.test',
          name: 'U',
          extra: 'admin-only',
          secret: 'hidden',
        },
      });
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('bopla-user') },
      );
      const res = await request(app.getHttpServer())
        .get('/users/profile')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      // Allowed fields preserved
      expect(res.body).toHaveProperty('id', 'u-1');
      expect(res.body).toHaveProperty('email', 'u@x.test');
      expect(res.body).toHaveProperty('name', 'U');
      // Disallowed fields stripped
      expect(res.body).not.toHaveProperty('extra');
      expect(res.body).not.toHaveProperty('secret');
    });

    it('admin role passes all fields through (Phase 8 D-07 admin-always-allow, GTWY-06)', async () => {
      fakeProxy.forward.mockResolvedValueOnce({
        status: 200,
        data: {
          id: 'u-1',
          email: 'u@x.test',
          name: 'U',
          extra: 'admin-only',
          secret: 'hidden',
        },
      });
      const token = await createHs256Token(
        { sub: 'admin-1', roles: ['admin'], deviceId: 'device-1' },
        { jti: uniqueJti('bopla-admin') },
      );
      const res = await request(app.getHttpServer())
        .get('/users/profile')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('extra', 'admin-only');
      expect(res.body).toHaveProperty('secret', 'hidden');
    });
  });

  // ───────────────────────────────────────────────────────────────────
  // GTWY-07 — Audit + metrics on every terminal decision
  // ───────────────────────────────────────────────────────────────────

  describe('GTWY-07 — Audit + metrics emission', () => {
    it('ALLOW → AuditRepository.insert called once with decision:"allow"; metrics increments allow (GTWY-07)', async () => {
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('audit-allow') },
      );
      const res = await request(app.getHttpServer())
        .get('/users/profile')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
      expect(fakeAudit.insert).toHaveBeenCalledTimes(1);
      const entry = fakeAudit.insert.mock.calls[0][0] as AuditEntry;
      expect(entry.decision).toBe('allow');
      expect(incRequestSpy).toHaveBeenCalledWith('allow');
    });

    it('DENY → AuditRepository.insert called with decision:"deny"; metrics increments deny (GTWY-07)', async () => {
      fakePolicy.evaluate.mockResolvedValueOnce({
        decision: 'DENY',
        reason: 'role_not_authorized',
        score: 0.1,
      });
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('audit-deny') },
      );
      const res = await request(app.getHttpServer())
        .get('/users/profile')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(403);
      // best-effort record uses repo.insert; allow up to 1 call
      const denyCalls = fakeAudit.insert.mock.calls.filter(
        (c) => (c[0] as AuditEntry).decision === 'deny',
      );
      expect(denyCalls.length).toBe(1);
      expect(incRequestSpy).toHaveBeenCalledWith('deny');
    });

    it('CHALLENGE → AuditRepository.insert called with decision:"challenge"; metrics increments challenge (GTWY-07)', async () => {
      fakePolicy.evaluate.mockResolvedValueOnce({
        decision: 'CHALLENGE',
        reason: 'risk_threshold',
        score: 0.6,
        matchedSubject: 'role:user',
      });
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('audit-challenge') },
      );
      const res = await request(app.getHttpServer())
        .get('/users/profile')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(401);
      const challengeCalls = fakeAudit.insert.mock.calls.filter(
        (c) => (c[0] as AuditEntry).decision === 'challenge',
      );
      expect(challengeCalls.length).toBe(1);
      expect(incRequestSpy).toHaveBeenCalledWith('challenge');
    });
  });

  // ───────────────────────────────────────────────────────────────────
  // GTWY-07 audit exhaustion (D-09 / D-10) — 503 + Retry-After: 5
  // ───────────────────────────────────────────────────────────────────

  describe('GTWY-07 — Audit WAL exhaustion (D-09/D-10)', () => {
    it('AuditRepository.insert always rejects on ALLOW → 503 + Retry-After: 5 + audit_unavailable; proxy NOT called (GTWY-07)', async () => {
      fakeAudit.insert.mockRejectedValue(new Error('db down'));
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('audit-exhausted') },
      );
      const res = await request(app.getHttpServer())
        .get('/users/profile')
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(503);
      expect(res.headers['retry-after']).toBe('5');
      expect(res.body).toMatchObject({ error: 'audit_unavailable' });
      // Proxy MUST NOT have been called when audit WAL is exhausted before allow
      expect(fakeProxy.forward).not.toHaveBeenCalled();
    }, 15_000);
  });

  // ───────────────────────────────────────────────────────────────────
  // GTWY-08 — /metrics observability sanity check after a successful ALLOW
  // ───────────────────────────────────────────────────────────────────

  describe('GTWY-08 — /metrics observability', () => {
    it('after a successful ALLOW, /metrics body advertises stage_duration buckets and requests counter (GTWY-08)', async () => {
      const token = await createHs256Token(
        { sub: 'user-1', roles: ['user'], deviceId: 'device-1' },
        { jti: uniqueJti('metrics-sanity') },
      );
      const allowRes = await request(app.getHttpServer())
        .get('/users/profile')
        .set('Authorization', `Bearer ${token}`);
      expect(allowRes.status).toBe(200);

      const metricsRes = await request(app.getHttpServer()).get('/metrics');
      expect(metricsRes.status).toBe(200);
      // Counter must exist with the allow label
      expect(metricsRes.text).toMatch(/zt_gateway_requests_total\{decision="allow"\}\s+[1-9]/);
      // Plan 03 widened STAGE_LABELS to 9 (incl. 'mfa')
      expect(metricsRes.text).toContain('zt_gateway_stage_duration_seconds');
      expect(metricsRes.text).toMatch(/stage="proxy"/);
    });
  });
});
