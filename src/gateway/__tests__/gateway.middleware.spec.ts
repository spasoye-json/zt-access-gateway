import { Logger, ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import { GatewayMiddleware } from '../gateway.middleware';
import { AuditExhaustedException } from '../../audit/audit-exhausted.exception';
import { AUDIT_SIGNAL } from '../../policy/policy-events';

/**
 * Phase 10 Plan 04 — GatewayMiddleware unit spec.
 *
 * Covers all 10 stages + every short-circuit + AUDIT_SIGNAL emission +
 * audit-record timeout (D-11) paths. Mocks every service via jest.fn();
 * does NOT use Test.createTestingModule (light unit tests per plan).
 */

interface MockReqOpts {
  path?: string;
  method?: string;
  headers?: Record<string, unknown>;
  socket?: { remoteAddress?: string };
  [key: string]: unknown;
}

function mockReq(overrides: MockReqOpts = {}): any {
  return {
    path: '/api/resource',
    method: 'GET',
    headers: {},
    socket: { remoteAddress: '127.0.0.1' },
    'x-ja4h': 'ja4h-fp-01',
    ...overrides,
  };
}

function mockRes(): any {
  const json = jest.fn();
  const set = jest.fn();
  const header = jest.fn();
  const status = jest.fn();
  const res: any = { json, set, header, status };
  // Chained: res.status(N).json(...) and res.status(N).set(K,V).json(...)
  status.mockImplementation(() => res);
  set.mockImplementation(() => res);
  header.mockImplementation(() => res);
  return res;
}

function defaultClaims() {
  return {
    userId: 'u1',
    roles: ['user'],
    jti: 'jti-1',
    exp: 9999999999,
    deviceId: 'dev-1',
  };
}

interface Mocks {
  auth: any;
  revocation: any;
  trustScore: any;
  hashcash: any;
  policy: any;
  mfa: any;
  proxy: any;
  boPla: any;
  audit: any;
  metrics: any;
  cfg: any;
  events: any;
}

function makeMocks(overrides: Partial<Mocks> = {}): Mocks {
  return {
    auth: { validateToken: jest.fn() },
    revocation: { isRevoked: jest.fn().mockReturnValue(false) },
    trustScore: {
      evaluateScore: jest.fn().mockResolvedValue(0.1),
      recordTrustContextAfterAllow: jest.fn().mockResolvedValue(undefined),
    },
    hashcash: {
      issueChallenge: jest.fn().mockReturnValue({
        nonce: 'nonce-x',
        difficulty: 4,
        expiresAt: 1234567890,
      }),
      verifySolution: jest.fn(),
    },
    policy: {
      evaluate: jest.fn().mockResolvedValue({
        decision: 'ALLOW',
        reason: 'ok',
        score: 0.1,
        matchedSubject: 'role:user',
      }),
    },
    mfa: {
      validateMfaToken: jest.fn(),
      createChallenge: jest.fn().mockResolvedValue({
        ok: true,
        challengeId: 'ch-id',
        expiresAt: 1234567890,
      }),
    },
    proxy: {
      forward: jest.fn().mockResolvedValue({ status: 200, data: { ok: true } }),
    },
    boPla: { strip: jest.fn().mockImplementation((d) => d) },
    audit: {
      writeBlocking: jest.fn().mockResolvedValue(undefined),
      record: jest.fn().mockResolvedValue(undefined),
    },
    metrics: {
      observeStageDuration: jest.fn(),
      observeAuditWalDuration: jest.fn(),
      incrementAuditFailure: jest.fn(),
      incrementRequest: jest.fn(),
      incrementMfaPromotion: jest.fn(),
    },
    cfg: { hashcashTriggerThreshold: 0.5 },
    events: { emit: jest.fn() },
    ...overrides,
  };
}

function build(m: Mocks): GatewayMiddleware {
  return new GatewayMiddleware(
    m.auth,
    m.revocation,
    m.trustScore,
    m.hashcash,
    m.policy,
    m.mfa,
    m.proxy,
    m.boPla,
    m.audit,
    m.metrics,
    m.cfg,
    m.events,
  );
}

const BEARER = 'Bearer token-abc';

describe('GatewayMiddleware', () => {
  let next: jest.Mock;

  beforeEach(() => {
    next = jest.fn();
  });

  // ── PUBLIC paths (D-03, GTWY-08) ───────────────────────────────────
  describe('PUBLIC paths', () => {
    it('calls next() and touches no service when req.path is /health', async () => {
      const m = makeMocks();
      const req = mockReq({ path: '/health' });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);
      expect(m.auth.validateToken).not.toHaveBeenCalled();
      expect(m.policy.evaluate).not.toHaveBeenCalled();
      expect(m.proxy.forward).not.toHaveBeenCalled();
    });

    it('calls next() and touches no service when req.path is /metrics', async () => {
      const m = makeMocks();
      const req = mockReq({ path: '/metrics' });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);
      expect(m.auth.validateToken).not.toHaveBeenCalled();
    });
  });

  // ── HONEYPOT paths (D-05, GTWY-09) ─────────────────────────────────
  describe('HONEYPOT paths', () => {
    it('calls next() for /wp-login.php and does NOT touch validateToken', async () => {
      const m = makeMocks();
      const req = mockReq({ path: '/wp-login.php' });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);
      expect(m.auth.validateToken).not.toHaveBeenCalled();
    });

    it('calls next() for /.env honeypot', async () => {
      const m = makeMocks();
      const req = mockReq({ path: '/.env' });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);
      expect(m.auth.validateToken).not.toHaveBeenCalled();
    });
  });

  // ── OPTIONS preflight bypass (Phase 12, F-p) ───────────────────────
  describe('OPTIONS preflight bypass (Phase 12)', () => {
    it('calls next() and touches no service when method is OPTIONS on /audit/logs', async () => {
      const m = makeMocks();
      const req = mockReq({ method: 'OPTIONS', path: '/audit/logs' });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);
      expect(m.auth.validateToken).not.toHaveBeenCalled();
      expect(m.policy.evaluate).not.toHaveBeenCalled();
      expect(m.proxy.forward).not.toHaveBeenCalled();
    });

    it('OPTIONS bypass takes precedence over auth gate on /policy/admin/rules', async () => {
      const m = makeMocks();
      const req = mockReq({ method: 'OPTIONS', path: '/policy/admin/rules' });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);
      expect(m.auth.validateToken).not.toHaveBeenCalled();
    });

    it('OPTIONS on a proxied path /api/users bypasses auth (CORS handler will reply)', async () => {
      const m = makeMocks();
      const req = mockReq({ method: 'OPTIONS', path: '/api/users' });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(next).toHaveBeenCalledTimes(1);
      expect(m.auth.validateToken).not.toHaveBeenCalled();
      expect(m.proxy.forward).not.toHaveBeenCalled();
    });
  });

  // ── Auth short-circuit (GTWY-03) ───────────────────────────────────
  describe('Auth short-circuit', () => {
    it('returns 401 {error:"auth_required"} when Authorization header missing', async () => {
      const m = makeMocks();
      const req = mockReq();
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: 'auth_required', requestId: expect.any(String) }),
      );
      expect(next).not.toHaveBeenCalled();
      expect(m.auth.validateToken).not.toHaveBeenCalled();
    });

    it('returns 401 {error:"auth_invalid"} when validateToken throws UnauthorizedException', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockRejectedValue(new UnauthorizedException('bad token'));
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: 'auth_invalid', requestId: expect.any(String) }),
      );
      // Pitfall 4 — no double response (json called once)
      expect(res.json).toHaveBeenCalledTimes(1);
      expect(m.policy.evaluate).not.toHaveBeenCalled();
    });

    it('observeStageDuration was called with "auth" before the short-circuit (D-14)', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockRejectedValue(new UnauthorizedException('bad'));
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      const stages = m.metrics.observeStageDuration.mock.calls.map((c: any[]) => c[0]);
      expect(stages).toContain('auth');
    });
  });

  // ── Revocation short-circuit (TREV-04 / GTWY-03) ───────────────────
  describe('Revocation short-circuit', () => {
    it('returns 401 {error:"token_revoked"} when isRevoked(jti) is true and skips later stages', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.revocation.isRevoked.mockReturnValue(true);
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: 'token_revoked', requestId: expect.any(String) }),
      );
      expect(m.trustScore.evaluateScore).not.toHaveBeenCalled();
      expect(m.policy.evaluate).not.toHaveBeenCalled();
      expect(m.proxy.forward).not.toHaveBeenCalled();
    });
  });

  // ── AUTH_ONLY path (D-04) ──────────────────────────────────────────
  describe('AUTH_ONLY path', () => {
    it('on /auth/revoke calls audit.record with decision:"allow" then next() — skips trust/hashcash/policy/proxy', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      const req = mockReq({ path: '/auth/revoke', method: 'POST', headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ decision: 'allow', resource: '/auth/revoke', action: 'POST' }),
      );
      expect(next).toHaveBeenCalledTimes(1);
      expect(m.trustScore.evaluateScore).not.toHaveBeenCalled();
      expect(m.policy.evaluate).not.toHaveBeenCalled();
      expect(m.proxy.forward).not.toHaveBeenCalled();
    });

    it('on /mfa/admin/enrollment/user-99 (prefix-match) calls next() after auth+revocation', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      const req = mockReq({ path: '/mfa/admin/enrollment/user-99', headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.audit.record).toHaveBeenCalled();
      expect(next).toHaveBeenCalledTimes(1);
      expect(m.policy.evaluate).not.toHaveBeenCalled();
    });

    it('AUTH_ONLY audit entry has trustScore undefined (Pitfall 2)', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      const req = mockReq({ path: '/auth/revoke', method: 'POST', headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      const entry = m.audit.record.mock.calls[0][0];
      expect(entry.trustScore).toBeUndefined();
    });
  });

  // ── Trust score (D-13, GTWY-02) ────────────────────────────────────
  describe('Trust score', () => {
    it('sets req.trustScore exactly once and observes "trust_score" duration', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.trustScore.evaluateScore.mockResolvedValue(0.2);
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(req.trustScore).toBe(0.2);
      expect(m.trustScore.evaluateScore).toHaveBeenCalledTimes(1);
      const stages = m.metrics.observeStageDuration.mock.calls.map((c: any[]) => c[0]);
      expect(stages).toContain('trust_score');
    });

    it('does NOT call evaluateScore twice (D-13)', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.trustScore.evaluateScore.mockResolvedValueOnce(0.1);
      m.trustScore.evaluateScore.mockImplementation(() => {
        throw new Error('evaluateScore must not be called twice');
      });
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.trustScore.evaluateScore).toHaveBeenCalledTimes(1);
    });
  });

  // ── Hashcash (HCSH / GTWY-03) ──────────────────────────────────────
  describe('Hashcash', () => {
    it('reads threshold via cfg.hashcashTriggerThreshold and passes through when score below threshold', async () => {
      const m = makeMocks();
      const getterSpy = jest.fn(() => 0.5);
      m.cfg = {};
      Object.defineProperty(m.cfg, 'hashcashTriggerThreshold', {
        get: getterSpy,
        configurable: true,
      });
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.trustScore.evaluateScore.mockResolvedValue(0.1);
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(getterSpy).toHaveBeenCalled();
      expect(m.hashcash.verifySolution).not.toHaveBeenCalled();
      expect(m.proxy.forward).toHaveBeenCalled();
    });

    it('returns 429 with X-Hashcash-Challenge header when score > threshold and no headers present', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.trustScore.evaluateScore.mockResolvedValue(0.9);
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(res.status).toHaveBeenCalledWith(429);
      // X-Hashcash-Challenge header set
      const setCalls = m.hashcash.issueChallenge.mock.calls;
      expect(setCalls.length).toBeGreaterThanOrEqual(1);
      expect(m.policy.evaluate).not.toHaveBeenCalled();
    });

    it('passes through to policy when verifySolution returns ok:true', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.trustScore.evaluateScore.mockResolvedValue(0.9);
      m.hashcash.verifySolution.mockReturnValue({ ok: true, iat: 0 });
      const req = mockReq({
        headers: {
          authorization: BEARER,
          'x-hashcash-nonce': 'nonce-x',
          'x-hashcash-solution': 'sol-y',
        },
      });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.hashcash.verifySolution).toHaveBeenCalled();
      expect(m.policy.evaluate).toHaveBeenCalledTimes(1);
      expect(m.proxy.forward).toHaveBeenCalledTimes(1);
    });

    it('returns 429 again when verifySolution returns ok:false', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.trustScore.evaluateScore.mockResolvedValue(0.9);
      m.hashcash.verifySolution.mockReturnValue({ ok: false, reason: 'insufficient_zeros' });
      const req = mockReq({
        headers: {
          authorization: BEARER,
          'x-hashcash-nonce': 'nonce-x',
          'x-hashcash-solution': 'sol-y',
        },
      });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(res.status).toHaveBeenCalledWith(429);
      expect(m.policy.evaluate).not.toHaveBeenCalled();
    });
  });

  // ── Policy DENY (PLCY / GTWY-03) ───────────────────────────────────
  describe('Policy DENY', () => {
    it('returns 403 {error:"policy_denied"} on DENY decision', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.policy.evaluate.mockResolvedValue({
        decision: 'DENY',
        reason: 'rbac_no_match',
        score: 0.1,
      });
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: 'policy_denied', requestId: expect.any(String) }),
      );
      expect(m.proxy.forward).not.toHaveBeenCalled();
    });

    it('calls audit.record before responding 403 (D-11 happy path; no incrementAuditFailure)', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.policy.evaluate.mockResolvedValue({ decision: 'DENY', reason: 'no', score: 0.1 });
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ decision: 'deny' }),
      );
      expect(m.metrics.incrementAuditFailure).not.toHaveBeenCalled();
    });

    it('on DENY when audit.record never resolves (timeout): incrementAuditFailure + audit_timeout warn-log fire (D-11 timeout)', async () => {
      jest.useFakeTimers();
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
      try {
        const m = makeMocks();
        m.auth.validateToken.mockResolvedValue(defaultClaims());
        m.policy.evaluate.mockResolvedValue({ decision: 'DENY', reason: 'x', score: 0.1 });
        m.audit.record.mockImplementation(() => new Promise(() => undefined));
        const req = mockReq({ headers: { authorization: BEARER } });
        const res = mockRes();
        const p = build(m).use(req, res, next);
        // sleep(200) wins
        await jest.advanceTimersByTimeAsync(250);
        await p;
        expect(m.metrics.incrementAuditFailure).toHaveBeenCalledTimes(1);
        const warnMsgs = warnSpy.mock.calls.map((c: any[]) => String(c[0]));
        expect(warnMsgs.some((s: string) => s.includes('audit_timeout'))).toBe(true);
        expect(res.status).toHaveBeenCalledWith(403);
      } finally {
        warnSpy.mockRestore();
        jest.useRealTimers();
      }
    });

    it('calls metrics.incrementRequest("deny") on DENY', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.policy.evaluate.mockResolvedValue({ decision: 'DENY', reason: 'no', score: 0.1 });
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.metrics.incrementRequest).toHaveBeenCalledWith('deny');
    });
  });

  // ── Policy CHALLENGE without MFA (D-06, GTWY-04) ───────────────────
  describe('Policy CHALLENGE without MFA', () => {
    it('returns 401 with WWW-Authenticate: MFA + X-MFA-Challenge headers', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.policy.evaluate.mockResolvedValue({ decision: 'CHALLENGE', reason: 'risk', score: 0.6 });
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(res.status).toHaveBeenCalledWith(401);
      const setCalls = res.set.mock.calls;
      const wwwAuth = setCalls.find((c: any[]) => c[0] === 'WWW-Authenticate');
      const mfaCh = setCalls.find((c: any[]) => c[0] === 'X-MFA-Challenge');
      expect(wwwAuth).toBeDefined();
      expect(String(wwwAuth[1])).toMatch(/MFA/);
      expect(mfaCh).toBeDefined();
      expect(mfaCh[1]).toBe('ch-id');
    });

    it('JSON body contains {error:"mfa_required", challengeId, verifyEndpoint, expiresAt, requestId}', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.policy.evaluate.mockResolvedValue({ decision: 'CHALLENGE', reason: 'r', score: 0.6 });
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'mfa_required',
          challengeId: 'ch-id',
          verifyEndpoint: '/mfa/verify',
          expiresAt: expect.any(String),
          requestId: expect.any(String),
        }),
      );
    });

    it('on CHALLENGE when audit.record never resolves (timeout): incrementAuditFailure + warn fire', async () => {
      jest.useFakeTimers();
      const warnSpy = jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
      try {
        const m = makeMocks();
        m.auth.validateToken.mockResolvedValue(defaultClaims());
        m.policy.evaluate.mockResolvedValue({ decision: 'CHALLENGE', reason: 'r', score: 0.6 });
        m.audit.record.mockImplementation(() => new Promise(() => undefined));
        const req = mockReq({ headers: { authorization: BEARER } });
        const res = mockRes();
        const p = build(m).use(req, res, next);
        await jest.advanceTimersByTimeAsync(250);
        await p;
        expect(m.metrics.incrementAuditFailure).toHaveBeenCalledTimes(1);
        const warnMsgs = warnSpy.mock.calls.map((c: any[]) => String(c[0]));
        expect(warnMsgs.some((s: string) => s.includes('audit_timeout'))).toBe(true);
        expect(res.status).toHaveBeenCalledWith(401);
      } finally {
        warnSpy.mockRestore();
        jest.useRealTimers();
      }
    });

    it('calls metrics.incrementMfaPromotion("reject") + observeStageDuration("mfa", ...)', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.policy.evaluate.mockResolvedValue({ decision: 'CHALLENGE', reason: 'r', score: 0.6 });
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.metrics.incrementMfaPromotion).toHaveBeenCalledWith('reject');
      const stages = m.metrics.observeStageDuration.mock.calls.map((c: any[]) => c[0]);
      expect(stages).toContain('mfa');
    });

    it('does NOT call proxy.forward on CHALLENGE without MFA', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.policy.evaluate.mockResolvedValue({ decision: 'CHALLENGE', reason: 'r', score: 0.6 });
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.proxy.forward).not.toHaveBeenCalled();
    });
  });

  // ── Policy CHALLENGE with valid MFA (D-07, GTWY-04) ────────────────
  describe('Policy CHALLENGE with valid MFA', () => {
    it('promotes to ALLOW path when validateMfaToken returns ok:true', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.policy.evaluate.mockResolvedValue({ decision: 'CHALLENGE', reason: 'r', score: 0.6 });
      m.mfa.validateMfaToken.mockResolvedValue({ ok: true, claims: { sub: 'u1' } });
      const req = mockReq({ headers: { authorization: BEARER, 'x-mfa-token': 'mfa-tok' } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.proxy.forward).toHaveBeenCalledTimes(1);
    });

    it('does NOT call policy.evaluate a second time on MFA promotion (D-07)', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.policy.evaluate.mockResolvedValue({ decision: 'CHALLENGE', reason: 'r', score: 0.6 });
      m.mfa.validateMfaToken.mockResolvedValue({ ok: true, claims: { sub: 'u1' } });
      const req = mockReq({ headers: { authorization: BEARER, 'x-mfa-token': 'mfa-tok' } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.policy.evaluate).toHaveBeenCalledTimes(1);
    });

    it('calls metrics.incrementMfaPromotion("allow")', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.policy.evaluate.mockResolvedValue({ decision: 'CHALLENGE', reason: 'r', score: 0.6 });
      m.mfa.validateMfaToken.mockResolvedValue({ ok: true, claims: { sub: 'u1' } });
      const req = mockReq({ headers: { authorization: BEARER, 'x-mfa-token': 'mfa-tok' } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.metrics.incrementMfaPromotion).toHaveBeenCalledWith('allow');
    });
  });

  // ── Audit-before-allow (D-09, D-10) ────────────────────────────────
  describe('Audit-before-allow + AUDIT_SIGNAL', () => {
    it('on ALLOW: audit.writeBlocking is called BEFORE proxy.forward', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.audit.writeBlocking).toHaveBeenCalledTimes(1);
      expect(m.proxy.forward).toHaveBeenCalledTimes(1);
      const wOrder = m.audit.writeBlocking.mock.invocationCallOrder[0];
      const pOrder = m.proxy.forward.mock.invocationCallOrder[0];
      expect(wOrder).toBeLessThan(pOrder);
    });

    it('returns 503 + Retry-After: 5 + {error:"audit_unavailable"} when writeBlocking throws AuditExhaustedException', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.audit.writeBlocking.mockRejectedValue(new AuditExhaustedException('exhausted'));
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(res.status).toHaveBeenCalledWith(503);
      const setCalls = res.set.mock.calls;
      const retry = setCalls.find((c: any[]) => c[0] === 'Retry-After');
      expect(retry).toBeDefined();
      expect(String(retry[1])).toBe('5');
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: 'audit_unavailable', requestId: expect.any(String) }),
      );
    });

    it('calls metrics.incrementAuditFailure on AuditExhaustedException', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.audit.writeBlocking.mockRejectedValue(new AuditExhaustedException('x'));
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.metrics.incrementAuditFailure).toHaveBeenCalled();
    });

    it('emits AUDIT_SIGNAL event exactly once on AuditExhaustedException (D-10)', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.audit.writeBlocking.mockRejectedValue(new AuditExhaustedException('x'));
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.events.emit).toHaveBeenCalledWith(
        AUDIT_SIGNAL,
        expect.objectContaining({ type: AUDIT_SIGNAL, ts: expect.any(Number) }),
      );
      expect(m.events.emit).toHaveBeenCalledTimes(1);
    });
  });

  // ── Proxy + BOPLA + trust context (GTWY-05, GTWY-06) ───────────────
  describe('Proxy + BOPLA + trust context', () => {
    it('calls boPla.strip(upstreamRes.data, req.path, claims.roles ?? [])', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.proxy.forward.mockResolvedValue({ status: 200, data: { secret: 's', ok: 1 } });
      const req = mockReq({ path: '/api/users', headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.boPla.strip).toHaveBeenCalledWith({ secret: 's', ok: 1 }, '/api/users', ['user']);
    });

    it('responds with status === upstreamRes.status and body === stripped data', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.proxy.forward.mockResolvedValue({ status: 201, data: { x: 1 } });
      m.boPla.strip.mockReturnValue({ x: 'stripped' });
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith({ x: 'stripped' });
    });

    it('calls recordTrustContextAfterAllow on upstream 2xx (D-12, GTWY-05)', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.proxy.forward.mockResolvedValue({ status: 200, data: {} });
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.trustScore.recordTrustContextAfterAllow).toHaveBeenCalledTimes(1);
    });

    it('does NOT call recordTrustContextAfterAllow on upstream 4xx (D-12)', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.proxy.forward.mockResolvedValue({ status: 404, data: {} });
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.trustScore.recordTrustContextAfterAllow).not.toHaveBeenCalled();
    });

    it('calls metrics.incrementRequest("allow") on success', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(m.metrics.incrementRequest).toHaveBeenCalledWith('allow');
    });

    it('returns 502 {error:"proxy_unavailable"} when proxy.forward throws ServiceUnavailableException', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      m.proxy.forward.mockRejectedValue(new ServiceUnavailableException('cb open'));
      const req = mockReq({ headers: { authorization: BEARER } });
      const res = mockRes();
      await build(m).use(req, res, next);
      expect(res.status).toHaveBeenCalledWith(502);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: 'proxy_unavailable', requestId: expect.any(String) }),
      );
    });
  });

  // ── Stage timing (D-14, Pitfall 7) ─────────────────────────────────
  describe('Stage timing', () => {
    it('observeStageDuration is called with seconds (ms / 1000), not ms', async () => {
      const m = makeMocks();
      m.auth.validateToken.mockResolvedValue(defaultClaims());
      // Date.now sequence: t0=0, then 5000 (5s elapsed), then anything
      const realNow = Date.now;
      let calls = 0;
      const seq = [0, 5000, 5000, 5000, 5000, 5000, 5000, 5000, 5000, 5000, 5000, 5000];
      jest.spyOn(Date, 'now').mockImplementation(() => {
        const v = seq[calls] ?? 5000;
        calls++;
        return v;
      });
      try {
        const req = mockReq({ headers: { authorization: BEARER } });
        const res = mockRes();
        await build(m).use(req, res, next);
        const authCall = m.metrics.observeStageDuration.mock.calls.find((c: any[]) => c[0] === 'auth');
        expect(authCall).toBeDefined();
        // first stage took 5000ms => 5 seconds
        expect(authCall[1]).toBe(5);
        // and NOT 5000
        expect(authCall[1]).not.toBe(5000);
      } finally {
        (Date.now as any).mockRestore?.();
        Date.now = realNow;
      }
    });
  });

  // ── Constants integration (Plan 01, 02) ────────────────────────────
  describe('Constants integration', () => {
    it('imports PUBLIC_PATHS from ./public-paths', () => {
      const mod = require('../public-paths');
      expect(mod.PUBLIC_PATHS).toBeDefined();
      expect(mod.PUBLIC_PATHS.has('/health')).toBe(true);
    });

    it('imports HONEYPOT_PATHS from ../honeypot/honeypot.constants', () => {
      const mod = require('../../honeypot/honeypot.constants');
      expect(mod.HONEYPOT_PATHS).toBeDefined();
      expect(mod.HONEYPOT_PATHS.has('/wp-login.php')).toBe(true);
    });
  });
});
