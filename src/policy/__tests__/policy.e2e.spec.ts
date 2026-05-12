/**
 * Phase 6 Plan 06 — full PLCY-01..PLCY-11 e2e cycle through real NestJS pipeline.
 *
 * Proves:
 *  - PLCY-01: Casbin enforcer boots from POLICY_MODEL_PATH + POLICY_CSV_PATH; GET /policy/admin/rules
 *    returns the 5 seeded rules (real HTTP).
 *  - PLCY-06: POST/DELETE /policy/admin/rules add/remove rules and persist write-through to a tmp CSV.
 *  - PLCY-08: cross-source aggregation (deny + invalid_token) drives Critical level.
 *  - PLCY-09: 25 emitted policy.deny events drive ThreatEscalationService to Elevated; thresholds tighten.
 *  - PLCY-11: GET/POST/DELETE /policy/admin/escalation introspection + manual override + clear.
 *  - D-03 runtime fail-closed: enforcer.enforce throw → DENY policy_error + emits policy.deny.
 *  - End-to-end emit wiring: missing Authorization → auth.invalid_token; honeypot route → honeypot.trigger.
 *  - Admin gate: non-admin token → 403 on POST /policy/admin/rules.
 *  - DTO validation: empty sub → 400 from global ValidationPipe.
 *
 * The canonical policy/policy.csv is NEVER mutated — POLICY_CSV_PATH points at a tmp copy.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// Set env BEFORE importing AppModule — ConfigModule validates at decoration time.
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = process.env.JWT_SECRET ?? 'test-secret-that-is-at-least-32-chars-long!';
process.env.HASHCASH_HMAC_SECRET = process.env.HASHCASH_HMAC_SECRET ?? 'a'.repeat(64);
process.env.HASHCASH_DIFFICULTY_MIN = '4';
process.env.HASHCASH_DIFFICULTY_MAX = '4';
process.env.HASHCASH_TRIGGER_THRESHOLD = process.env.HASHCASH_TRIGGER_THRESHOLD ?? '0.7';
if (!process.env.MTLS_CA_CERT_PATH) process.env.MTLS_CA_CERT_PATH = '/dev/null';
if (!process.env.MTLS_CLIENT_CERT_PATH) process.env.MTLS_CLIENT_CERT_PATH = '/dev/null';
if (!process.env.MTLS_CLIENT_KEY_PATH) process.env.MTLS_CLIENT_KEY_PATH = '/dev/null';
if (!process.env.MTLS_ALLOWED_SUBJECTS) process.env.MTLS_ALLOWED_SUBJECTS = 'cn=test';
if (!process.env.DATABASE_URL) process.env.DATABASE_URL = 'postgresql://localhost:5432/zt_test';
// Phase 7 MFA vars — required by config validation after MfaModule added to AppModule
if (!process.env.MFA_JWT_SECRET)
  process.env.MFA_JWT_SECRET = 'mfa-test-secret-that-is-at-least-32-chars!!';
if (!process.env.MFA_TOTP_ENCRYPTION_KEY)
  process.env.MFA_TOTP_ENCRYPTION_KEY = Buffer.from('a'.repeat(32)).toString('base64');
// Phase 8 Proxy vars — required by config validation after ProxyModule added to AppModule
if (!process.env.PROXY_SERVICE_REGISTRY)
  process.env.PROXY_SERVICE_REGISTRY = JSON.stringify({ dummy: 'https://dummy.test:8443' });

// Tmp CSV — PolicyEvaluator will write through here on POST/DELETE rules.
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'policy-e2e-'));
const tmpCsv = path.join(tmpDir, 'policy.csv');
fs.copyFileSync(path.join(process.cwd(), 'policy/policy.csv'), tmpCsv);
process.env.POLICY_CSV_PATH = tmpCsv;
process.env.POLICY_MODEL_PATH = path.join(process.cwd(), 'policy/model.conf');

import { Test } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import * as request from 'supertest';
import { AppModule } from '../../app.module';
import { TrustScoreService } from '../../trust-score/trust-score.service';
import { ThreatEscalationService } from '../threat-escalation.service';
import { PolicyEvaluatorService } from '../policy-evaluator.service';
import { AUTH_INVALID_TOKEN, POLICY_DENY, type ThreatSignalPayload } from '../policy-events';
import { createHs256Token } from '../../auth/__tests__/test-keys';

// Phase 10 D-01/D-02: GatewayMiddleware now runs as global middleware in
// AppModule and the JwtAuthGuard / HashcashGuard APP_GUARDs were removed
// (plan 10-05). This e2e was authored against the pre-Phase-10 model where
// Casbin policy decisions were enforced via per-route guards on raw paths.
// In the new model the gateway pipeline either short-circuits AUTH_ONLY paths
// or rewrites the dispatch to mTLS proxy forwarding — neither of which the
// existing assertions expect. Plan 10-06 owns the rewritten full-pipeline
// e2e (ALLOW/CHALLENGE/DENY/honeypot/auth_only branches against a registered
// proxy service). Skipping here documents the migration.
describe.skip('Policy + Threat Escalation — E2E (superseded by plan 10-06 GatewayMiddleware e2e)', () => {
  let app: INestApplication;
  let adminToken: string;
  let userToken: string;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(TrustScoreService)
      .useValue({
        evaluateScore: jest.fn().mockResolvedValue(0.1),
        recordTrustContextAfterAllow: jest.fn(),
      })
      .compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        transform: true,
        whitelist: true,
        forbidNonWhitelisted: true,
      }),
    );
    await app.init();

    adminToken = await createHs256Token(
      { sub: 'admin-1', roles: ['admin'] },
      { jti: 'jti-admin-e2e' },
    );
    userToken = await createHs256Token({ sub: 'user-1', roles: ['user'] }, { jti: 'jti-user-e2e' });
  });

  afterAll(async () => {
    await app?.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  beforeEach(() => {
    // Pitfall 7 isolation: clear escalation override and flush any test-induced signals.
    const threat = app.get(ThreatEscalationService);
    threat.clearManualLevel();
    (threat as unknown as { events: unknown[] }).events.length = 0;
    (threat as unknown as { level: string }).level = 'Normal';
    (threat as unknown as { manualOverride: unknown }).manualOverride = null;
  });

  // ── PLCY-01 ───────────────────────────────────────────────────────────────
  it('PLCY-01: GET /policy/admin/rules returns the 5 seeded rules', async () => {
    const res = await request(app.getHttpServer())
      .get('/policy/admin/rules')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('x-ja4h', 'fp-admin')
      .expect(200);
    expect(res.body.rules).toEqual(expect.arrayContaining([['role:user', '/users', 'GET']]));
    expect(res.body.rules.length).toBeGreaterThanOrEqual(5);
  });

  // ── PLCY-06 add ───────────────────────────────────────────────────────────
  it('PLCY-06: POST /policy/admin/rules adds a rule and persists to tmp CSV', async () => {
    await request(app.getHttpServer())
      .post('/policy/admin/rules')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('x-ja4h', 'fp-admin')
      .send({ sub: 'role:tester', obj: '/test', act: 'GET' })
      .expect(200)
      .expect({ added: true });

    const csv = fs.readFileSync(tmpCsv, 'utf8');
    expect(csv).toContain('role:tester');
    expect(csv).toContain('/test');
  });

  // ── PLCY-06 remove ────────────────────────────────────────────────────────
  it('PLCY-06: DELETE /policy/admin/rules removes a rule and persists to tmp CSV', async () => {
    // Ensure rule exists first (if a previous test removed it, re-add).
    await request(app.getHttpServer())
      .post('/policy/admin/rules')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('x-ja4h', 'fp-admin')
      .send({ sub: 'role:tester', obj: '/test', act: 'GET' });

    await request(app.getHttpServer())
      .delete('/policy/admin/rules')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('x-ja4h', 'fp-admin')
      .send({ sub: 'role:tester', obj: '/test', act: 'GET' })
      .expect(200)
      .expect({ removed: true });

    const csv = fs.readFileSync(tmpCsv, 'utf8');
    expect(csv).not.toContain('role:tester');
  });

  // ── Admin gate (PLCY-06 + PLCY-11) ────────────────────────────────────────
  it('non-admin token on POST /policy/admin/rules → 403', async () => {
    await request(app.getHttpServer())
      .post('/policy/admin/rules')
      .set('Authorization', `Bearer ${userToken}`)
      .set('x-ja4h', 'fp-user')
      .send({ sub: 'role:hack', obj: '/x', act: 'GET' })
      .expect(403);
  });

  // ── DTO validation ────────────────────────────────────────────────────────
  it('DTO validation: empty sub → 400', async () => {
    await request(app.getHttpServer())
      .post('/policy/admin/rules')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('x-ja4h', 'fp-admin')
      .send({ sub: '', obj: '/x', act: 'GET' })
      .expect(400);
  });

  // ── PLCY-11 GET escalation default Normal ─────────────────────────────────
  it('PLCY-11: GET /policy/admin/escalation reports Normal by default', async () => {
    const res = await request(app.getHttpServer())
      .get('/policy/admin/escalation')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('x-ja4h', 'fp-admin')
      .expect(200);
    expect(res.body).toMatchObject({
      level: 'Normal',
      override: null,
      activeThresholds: { challenge: 0.5, deny: 0.8 },
    });
  });

  // ── PLCY-11 POST escalation sets override; thresholds tighten ─────────────
  it('PLCY-11: POST /policy/admin/escalation sets override; thresholds tighten', async () => {
    await request(app.getHttpServer())
      .post('/policy/admin/escalation')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('x-ja4h', 'fp-admin')
      .send({ level: 'Critical' })
      .expect(200)
      .expect({ ok: true, level: 'Critical' });

    const res = await request(app.getHttpServer())
      .get('/policy/admin/escalation')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('x-ja4h', 'fp-admin')
      .expect(200);
    expect(res.body).toMatchObject({
      level: 'Critical',
      override: 'Critical',
      activeThresholds: { challenge: 0.2, deny: 0.4 },
    });
  });

  // ── PLCY-11 DELETE clears override ────────────────────────────────────────
  it('PLCY-11: DELETE /policy/admin/escalation clears override', async () => {
    await request(app.getHttpServer())
      .post('/policy/admin/escalation')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('x-ja4h', 'fp-admin')
      .send({ level: 'Critical' });

    await request(app.getHttpServer())
      .delete('/policy/admin/escalation')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('x-ja4h', 'fp-admin')
      .expect(200)
      .expect({ ok: true });

    const res = await request(app.getHttpServer())
      .get('/policy/admin/escalation')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('x-ja4h', 'fp-admin');
    expect(res.body.override).toBeNull();
  });

  // ── PLCY-09 auto-tightening via emitted policy.deny events ────────────────
  it('PLCY-09: 25 policy.deny events drive level to Elevated; thresholds tighten', async () => {
    const emitter = app.get(EventEmitter2);
    for (let i = 0; i < 25; i++) {
      const payload: ThreatSignalPayload = {
        type: POLICY_DENY,
        ip: '1.2.3.4',
        ts: Date.now(),
      };
      emitter.emit(POLICY_DENY, payload);
    }
    const res = await request(app.getHttpServer())
      .get('/policy/admin/escalation')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('x-ja4h', 'fp-admin');
    expect(res.body.level).toBe('Elevated');
    expect(res.body.activeThresholds).toEqual({ challenge: 0.3, deny: 0.6 });
  });

  // ── PLCY-08 cross-source aggregation ──────────────────────────────────────
  it('PLCY-08: deny + invalid_token mix → Critical (max-across-types)', async () => {
    const emitter = app.get(EventEmitter2);
    for (let i = 0; i < 25; i++) {
      emitter.emit(POLICY_DENY, {
        type: POLICY_DENY,
        ip: '1.1.1.1',
        ts: Date.now(),
      });
    }
    for (let i = 0; i < 80; i++) {
      emitter.emit(AUTH_INVALID_TOKEN, {
        type: AUTH_INVALID_TOKEN,
        ip: '1.1.1.1',
        ts: Date.now(),
      });
    }
    const res = await request(app.getHttpServer())
      .get('/policy/admin/escalation')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('x-ja4h', 'fp-admin');
    expect(res.body.level).toBe('Critical');
  });

  // ── PLCY-08 auth.invalid_token wired end-to-end ───────────────────────────
  it('PLCY-08: missing Authorization header increments signalCounts.auth.invalid_token', async () => {
    await request(app.getHttpServer())
      .get('/policy/admin/rules')
      .set('x-ja4h', 'fp-anon')
      .expect(401);
    const threat = app.get(ThreatEscalationService);
    expect(threat.snapshot().signalCounts['auth.invalid_token']).toBeGreaterThanOrEqual(1);
  });

  // ── PLCY-08 honeypot.trigger wired end-to-end ─────────────────────────────
  it('PLCY-08: GET /wp-login.php increments signalCounts.honeypot.trigger', async () => {
    await request(app.getHttpServer()).get('/wp-login.php').set('x-ja4h', 'fp-scan').expect(200);
    const threat = app.get(ThreatEscalationService);
    expect(threat.snapshot().signalCounts['honeypot.trigger']).toBeGreaterThanOrEqual(1);
  }, 10000);

  // ── D-03 fail-closed runtime ──────────────────────────────────────────────
  it('D-03 fail-closed: enforce() throw → DENY policy_error AND emits policy.deny', async () => {
    const evaluator = app.get(PolicyEvaluatorService);
    const emitter = app.get(EventEmitter2);
    const spy = jest.spyOn(emitter, 'emit');
    const enforcer = (evaluator as unknown as { enforcer: { enforce: jest.Mock } }).enforcer;
    jest.spyOn(enforcer, 'enforce').mockRejectedValueOnce(new Error('boom'));

    const fakeReq = {
      path: '/users',
      method: 'GET',
      user: {
        userId: '1',
        roles: ['user'],
        deviceId: 'd',
        jti: 'j',
      },
      headers: { 'x-ja4h': 'jh' },
      ip: '1.1.1.1',
      socket: { remoteAddress: '1.1.1.1' },
    } as unknown as Parameters<typeof evaluator.evaluate>[0];

    const r = await evaluator.evaluate(fakeReq);
    expect(r.decision).toBe('DENY');
    expect((r as { reason: string }).reason).toBe('policy_error');
    expect(spy).toHaveBeenCalledWith(POLICY_DENY, expect.any(Object));
    spy.mockRestore();
  });

  // ── PLCY-06 + PLCY-09: combined add-rule + signal-driven escalation ───────
  it('PLCY-06 + PLCY-09: rules CRUD continues to work after escalation transitions', async () => {
    const emitter = app.get(EventEmitter2);
    for (let i = 0; i < 25; i++) {
      emitter.emit(POLICY_DENY, {
        type: POLICY_DENY,
        ip: '9.9.9.9',
        ts: Date.now(),
      });
    }

    await request(app.getHttpServer())
      .post('/policy/admin/rules')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('x-ja4h', 'fp-admin')
      .send({ sub: 'role:auditor', obj: '/audit', act: 'GET' })
      .expect(200)
      .expect({ added: true });

    await request(app.getHttpServer())
      .delete('/policy/admin/rules')
      .set('Authorization', `Bearer ${adminToken}`)
      .set('x-ja4h', 'fp-admin')
      .send({ sub: 'role:auditor', obj: '/audit', act: 'GET' })
      .expect(200)
      .expect({ removed: true });
  });
});
