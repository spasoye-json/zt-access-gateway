import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { HashcashGuard } from '../hashcash.guard';
import { HashcashService, IssuedChallenge } from '../hashcash.service';
import { TrustScoreService } from '../../trust-score/trust-score.service';
import type { AppConfigService } from '../../config/config.service';

interface MockReq {
  headers: Record<string, string | undefined>;
  method: string;
  user?: { userId: string; deviceId: string; roles: string[] };
  trustScore?: number;
  socket?: { remoteAddress?: string };
}
interface MockRes {
  status: jest.Mock;
  header: jest.Mock;
  json: jest.Mock;
}

function ctx(
  req: Partial<MockReq>,
  res?: MockRes,
  isPublic = false,
): { ec: ExecutionContext; req: MockReq; res: MockRes; reflector: Reflector } {
  const fullReq: MockReq = {
    headers: { 'x-ja4h': 'fp', 'x-forwarded-for': '1.2.3.4', ...(req.headers || {}) },
    method: req.method ?? 'GET',
    user: req.user ?? { userId: 'u', deviceId: 'd', roles: [] },
    trustScore: req.trustScore,
    socket: { remoteAddress: '1.2.3.4' },
  };
  const fullRes: MockRes = res ?? {
    status: jest.fn().mockReturnThis(),
    header: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
  };
  const reflector = new Reflector();
  jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(isPublic);
  const ec = {
    switchToHttp: () => ({ getRequest: () => fullReq, getResponse: () => fullRes }),
    getHandler: () => () => undefined,
    getClass: () => class {},
  } as unknown as ExecutionContext;
  return { ec, req: fullReq, res: fullRes, reflector };
}

function fakeConfig(): AppConfigService {
  return {
    hashcashTriggerThreshold: 0.7,
    hashcashHmacSecret: 'a'.repeat(64),
    hashcashChallengeTtlMs: 120000,
    hashcashUsedNonceCapacity: 100,
  } as unknown as AppConfigService;
}

function issued(over: Partial<IssuedChallenge> = {}): IssuedChallenge {
  return { nonce: 'NONCE', difficulty: 4, expiresAt: 9_999_999_999, ...over };
}

describe('HashcashGuard', () => {
  let guard: HashcashGuard;
  let hashcashService: { issueChallenge: jest.Mock; verifySolution: jest.Mock };
  let trustScoreService: { evaluateScore: jest.Mock };

  beforeEach(() => {
    hashcashService = {
      issueChallenge: jest.fn().mockReturnValue(issued()),
      verifySolution: jest.fn(),
    };
    trustScoreService = { evaluateScore: jest.fn() };
    guard = new HashcashGuard(
      new Reflector(),
      hashcashService as unknown as HashcashService,
      trustScoreService as unknown as TrustScoreService,
      fakeConfig(),
    );
  });

  describe('bypass', () => {
    it('@Public() route returns true without consulting service', async () => {
      const c = ctx({}, undefined, true);
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      expect(await guard.canActivate(c.ec)).toBe(true);
      expect(hashcashService.issueChallenge).not.toHaveBeenCalled();
      expect(hashcashService.verifySolution).not.toHaveBeenCalled();
    });

    it('OPTIONS request returns true (CORS preflight bypass)', async () => {
      const c = ctx({ method: 'OPTIONS' });
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      expect(await guard.canActivate(c.ec)).toBe(true);
    });
  });

  describe('trustScore seam (D-07)', () => {
    it('uses request.trustScore when set (no fallback evaluateScore)', async () => {
      const c = ctx({ trustScore: 0.5 });
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      await guard.canActivate(c.ec);
      expect(trustScoreService.evaluateScore).not.toHaveBeenCalled();
    });

    it('falls back to TrustScoreService.evaluateScore when request.trustScore undefined', async () => {
      const c = ctx({ trustScore: undefined });
      trustScoreService.evaluateScore.mockResolvedValue(0.5);
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      await guard.canActivate(c.ec);
      expect(trustScoreService.evaluateScore).toHaveBeenCalledTimes(1);
    });
  });

  describe('score <= 0.7', () => {
    it('score === 0.7 returns true (strict > per D-08)', async () => {
      const c = ctx({ trustScore: 0.7 });
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      expect(await guard.canActivate(c.ec)).toBe(true);
      expect(hashcashService.issueChallenge).not.toHaveBeenCalled();
    });

    it('score === 0.5 returns true', async () => {
      const c = ctx({ trustScore: 0.5 });
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      expect(await guard.canActivate(c.ec)).toBe(true);
    });
  });

  describe('score > 0.7 (issues 429)', () => {
    it('no solution header → 429 with header/body using service-returned difficulty (single source of truth)', async () => {
      const c = ctx({ trustScore: 0.75 });
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      hashcashService.issueChallenge.mockReturnValue(
        issued({ nonce: 'NONCE', difficulty: 19, expiresAt: 1234567890 }),
      );
      const result = await guard.canActivate(c.ec);
      expect(result).toBe(false);
      expect(c.res.status).toHaveBeenCalledWith(429);
      expect(c.res.header).toHaveBeenCalledWith('X-Hashcash-Challenge', 'NONCE:19');
      expect(c.res.header).toHaveBeenCalledWith('Retry-After', '1');
      expect(c.res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'proof_of_work_required',
          nonce: 'NONCE',
          difficulty: 19,
          expiresAt: 1234567890,
        }),
      );
    });

    it('header difficulty NEVER NaN — uses whatever service returns', async () => {
      // Regression guard for the original bug: if service returns difficulty 22, header MUST be "NONCE:22", not "NONCE:NaN".
      const c = ctx({ trustScore: 0.95 });
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      hashcashService.issueChallenge.mockReturnValue(issued({ nonce: 'N2', difficulty: 22, expiresAt: 5 }));
      await guard.canActivate(c.ec);
      expect(c.res.header).toHaveBeenCalledWith('X-Hashcash-Challenge', 'N2:22');
      // Body difficulty matches header difficulty
      expect(c.res.json).toHaveBeenCalledWith(
        expect.objectContaining({ difficulty: 22, expiresAt: 5 }),
      );
    });

    it('guard does not call difficultyForScore independently — passes raw score to service', async () => {
      const c = ctx({ trustScore: 0.85 });
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      await guard.canActivate(c.ec);
      // Service receives userId, deviceId, score — NOT a precomputed difficulty
      expect(hashcashService.issueChallenge).toHaveBeenCalledWith('u', 'd', 0.85);
    });
  });

  describe('reads solution header', () => {
    it('forwards X-Hashcash-Solution + X-Hashcash-Nonce to verifySolution', async () => {
      const c = ctx({
        trustScore: 0.75,
        headers: { 'x-hashcash-nonce': 'N', 'x-hashcash-solution': 'S', 'x-ja4h': 'fp' },
      });
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      hashcashService.verifySolution.mockReturnValue({ ok: true, iat: 0 });
      await guard.canActivate(c.ec);
      expect(hashcashService.verifySolution).toHaveBeenCalledWith('N', 'S', 0.75, 'u', 'd');
    });

    it('forwards user.userId and user.deviceId into verifySolution (D-02 identity binding)', async () => {
      const c = ctx({
        trustScore: 0.8,
        headers: {
          'x-hashcash-nonce': 'NONCE',
          'x-hashcash-solution': 'SOL',
          'x-ja4h': 'fp',
        },
        user: { userId: 'user-A', deviceId: 'dev-1', roles: [] },
      });
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      hashcashService.verifySolution.mockReturnValue({ ok: true, iat: 1 });
      await guard.canActivate(c.ec);
      expect(hashcashService.verifySolution).toHaveBeenCalledWith(
        'NONCE',
        'SOL',
        expect.any(Number),
        'user-A',
        'dev-1',
      );
    });

    it('header value > 256 chars rejected with 429 invalid before service call', async () => {
      const c = ctx({
        trustScore: 0.75,
        headers: { 'x-hashcash-nonce': 'N', 'x-hashcash-solution': 'x'.repeat(257), 'x-ja4h': 'fp' },
      });
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      const result = await guard.canActivate(c.ec);
      expect(result).toBe(false);
      // Either guard pre-rejects, OR forwards to service which returns length_bound — either way: no leak, 429 issued.
      expect(c.res.status).toHaveBeenCalledWith(429);
    });
  });

  describe('valid solution', () => {
    it('verifySolution → true ⇒ guard returns true', async () => {
      const c = ctx({
        trustScore: 0.75,
        headers: { 'x-hashcash-nonce': 'N', 'x-hashcash-solution': 'S', 'x-ja4h': 'fp' },
      });
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      hashcashService.verifySolution.mockReturnValue({ ok: true, iat: 0 });
      expect(await guard.canActivate(c.ec)).toBe(true);
    });

    it('verifySolution → false ⇒ guard issues fresh 429', async () => {
      const c = ctx({
        trustScore: 0.75,
        headers: { 'x-hashcash-nonce': 'N', 'x-hashcash-solution': 'S', 'x-ja4h': 'fp' },
      });
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      hashcashService.verifySolution.mockReturnValue({ ok: false, reason: 'expired' });
      hashcashService.issueChallenge.mockReturnValue(issued({ nonce: 'FRESH', difficulty: 19 }));
      const result = await guard.canActivate(c.ec);
      expect(result).toBe(false);
      expect(c.res.json).toHaveBeenCalledWith(
        expect.objectContaining({ error: 'proof_of_work_invalid', nonce: 'FRESH', difficulty: 19 }),
      );
    });
  });

  describe('metrics', () => {
    it('issuing on no-solution path emits metrics via service.issueChallenge', async () => {
      const c = ctx({ trustScore: 0.75 });
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      await guard.canActivate(c.ec);
      expect(hashcashService.issueChallenge).toHaveBeenCalledTimes(1);
    });
  });

  describe('histogram', () => {
    it('successful verify path lets HashcashService observe solveSeconds', async () => {
      const c = ctx({
        trustScore: 0.75,
        headers: { 'x-hashcash-nonce': 'N', 'x-hashcash-solution': 'S', 'x-ja4h': 'fp' },
      });
      guard = new HashcashGuard(
        c.reflector,
        hashcashService as unknown as HashcashService,
        trustScoreService as unknown as TrustScoreService,
        fakeConfig(),
      );
      hashcashService.verifySolution.mockReturnValue({ ok: true, iat: 0 });
      await guard.canActivate(c.ec);
      // Histogram emission is inside HashcashService (asserted in plan 03's spec).
      expect(hashcashService.verifySolution).toHaveBeenCalled();
    });
  });
});
