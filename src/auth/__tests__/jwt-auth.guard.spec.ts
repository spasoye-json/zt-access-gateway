import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { JwtAuthGuard } from '../jwt-auth.guard';
import { AuthService } from '../auth.service';
import { TokenRevocationService } from '../token-revocation.service';
import { AUTH_INVALID_TOKEN } from '../../policy/policy-events';
import { GATEWAY_VALIDATED } from '../../gateway/gateway-validated.symbol';
import { createHs256Token } from './test-keys';

/**
 * JwtAuthGuard unit tests -- TDD RED phase.
 * Tests will fail on import until jwt-auth.guard.ts is created in Wave 1.
 *
 * Coverage: AUTH-06, AUTH-07, TREV-04
 */
describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;
  let reflector: Reflector;
  let authService: Partial<AuthService>;
  let revocationService: Partial<TokenRevocationService>;
  let events: EventEmitter2;

  function createMockExecutionContext(overrides?: {
    authorization?: string;
    isPublic?: boolean;
    roles?: string[];
    ip?: string;
    ja4h?: string;
    gatewayValidated?: boolean;
    user?: unknown;
  }): ExecutionContext {
    // WR-04: emitInvalid now routes through extractIp, which reads
    // headers['x-forwarded-for'] then falls back to socket.remoteAddress.
    // Tests still pass `ip` for readability; the mock plumbs it through
    // socket.remoteAddress so extractIp returns the expected value.
    const ip = overrides?.ip ?? '1.2.3.4';
    const request: Record<string, unknown> = {
      headers: {
        ...(overrides?.authorization !== undefined
          ? { authorization: overrides.authorization }
          : {}),
      },
      ip,
      socket: { remoteAddress: ip },
      user: undefined,
    };
    if (overrides?.ja4h !== undefined) {
      request['x-ja4h'] = overrides.ja4h;
    }
    if (overrides?.gatewayValidated === true) {
      (request as Record<symbol, unknown>)[GATEWAY_VALIDATED] = true;
    }
    if (overrides?.user !== undefined) {
      request.user = overrides.user;
    }

    const handler = {} as () => void;
    const classRef = {} as () => void;

    return {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({}),
        getNext: () => ({}),
      }),
      getHandler: () => handler,
      getClass: () => classRef,
      getType: () => 'http',
      getArgs: () => [],
      getArgByIndex: () => undefined,
      switchToRpc: () => ({}) as ReturnType<ExecutionContext['switchToRpc']>,
      switchToWs: () => ({}) as ReturnType<ExecutionContext['switchToWs']>,
    } as unknown as ExecutionContext;
  }

  beforeEach(() => {
    reflector = new Reflector();
    authService = {
      validateToken: jest.fn(),
    };
    revocationService = {
      isRevoked: jest.fn().mockReturnValue(false),
    };
    events = new EventEmitter2();

    guard = new JwtAuthGuard(
      reflector,
      authService as AuthService,
      revocationService as TokenRevocationService,
      events,
    );
  });

  describe('@Public() bypass (AUTH-07)', () => {
    it('returns true without validating token when route is @Public()', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(true);

      const ctx = createMockExecutionContext();
      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(authService.validateToken).not.toHaveBeenCalled();
    });

    it('proceeds to validate token when route is NOT @Public()', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);

      const token = await createHs256Token({ sub: 'u1', roles: ['user'] }, { jti: 'jti-1' });
      const ctx = createMockExecutionContext({
        authorization: `Bearer ${token}`,
      });

      (authService.validateToken as jest.Mock).mockResolvedValue({
        userId: 'u1',
        roles: ['user'],
        jti: 'jti-1',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });

      await guard.canActivate(ctx);
      expect(authService.validateToken).toHaveBeenCalledWith(token);
    });
  });

  describe('GatewayMiddleware sentinel short-circuit (Phase 13 D-04/D-05)', () => {
    it('sentinel-present → returns true and does NOT call validateToken / isRevoked / emit', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      const emitSpy = jest.spyOn(events, 'emit');

      const ctx = createMockExecutionContext({
        gatewayValidated: true,
        user: {
          userId: 'u-gw',
          roles: ['user'],
          jti: 'jti-gw',
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
      });

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(authService.validateToken).not.toHaveBeenCalled();
      expect(revocationService.isRevoked).not.toHaveBeenCalled();
      expect(emitSpy).not.toHaveBeenCalled();
    });

    it('sentinel-absent → calls validateToken exactly once (standalone-route fallback per D-07)', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      (authService.validateToken as jest.Mock).mockResolvedValue({
        userId: 'u-standalone',
        roles: ['user'],
        jti: 'jti-standalone',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });

      const token = await createHs256Token(
        { sub: 'u-standalone', roles: ['user'] },
        { jti: 'jti-standalone' },
      );
      const ctx = createMockExecutionContext({
        authorization: `Bearer ${token}`,
        // gatewayValidated NOT set
      });

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(authService.validateToken).toHaveBeenCalledTimes(1);
    });

    it('string-valued sentinel header does NOT bypass (D-04 spoof safety — Symbol identity is the only authority)', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      (authService.validateToken as jest.Mock).mockResolvedValue({
        userId: 'u-spoof',
        roles: ['user'],
        jti: 'jti-spoof',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });

      const token = await createHs256Token(
        { sub: 'u-spoof', roles: ['user'] },
        { jti: 'jti-spoof' },
      );
      const ctx = createMockExecutionContext({
        authorization: `Bearer ${token}`,
      });
      // Attempt spoof — string key, NOT the Symbol.
      const req = ctx.switchToHttp().getRequest();
      req['GATEWAY_VALIDATED'] = true;
      (req.headers as Record<string, string>)['x-gateway-validated'] = 'true';

      await guard.canActivate(ctx);

      // Spoof failed: full validation path ran.
      expect(authService.validateToken).toHaveBeenCalledTimes(1);
    });
  });

  describe('Bearer extraction (AUTH-06)', () => {
    it('extracts token from Authorization: Bearer <token> header', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);

      const token = await createHs256Token({ sub: 'u1', roles: ['user'] }, { jti: 'jti-extract' });
      const ctx = createMockExecutionContext({
        authorization: `Bearer ${token}`,
      });

      (authService.validateToken as jest.Mock).mockResolvedValue({
        userId: 'u1',
        roles: ['user'],
        jti: 'jti-extract',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });

      await guard.canActivate(ctx);
      expect(authService.validateToken).toHaveBeenCalledWith(token);
    });

    it('throws UnauthorizedException when Authorization header missing', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);

      const ctx = createMockExecutionContext();

      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
    });

    it('throws UnauthorizedException when Authorization header not Bearer scheme', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);

      const ctx = createMockExecutionContext({
        authorization: 'Basic dXNlcjpwYXNz',
      });

      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('UserClaims attachment (AUTH-06)', () => {
    it('attaches validated UserClaims to request.user', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);

      const expectedClaims = {
        userId: 'u1',
        roles: ['user'],
        jti: 'jti-attach',
        exp: Math.floor(Date.now() / 1000) + 3600,
      };
      (authService.validateToken as jest.Mock).mockResolvedValue(expectedClaims);

      const token = await createHs256Token({ sub: 'u1', roles: ['user'] }, { jti: 'jti-attach' });
      const ctx = createMockExecutionContext({
        authorization: `Bearer ${token}`,
      });

      await guard.canActivate(ctx);

      const request = ctx.switchToHttp().getRequest();
      expect(request.user).toEqual(expectedClaims);
    });
  });

  describe('revocation check (TREV-04, D-08)', () => {
    it('throws UnauthorizedException("Token has been revoked") when jti is revoked', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);

      const claims = {
        userId: 'u1',
        roles: ['user'],
        jti: 'revoked-jti',
        exp: Math.floor(Date.now() / 1000) + 3600,
      };
      (authService.validateToken as jest.Mock).mockResolvedValue(claims);
      (revocationService.isRevoked as jest.Mock).mockReturnValue(true);

      const token = await createHs256Token({ sub: 'u1', roles: ['user'] }, { jti: 'revoked-jti' });
      const ctx = createMockExecutionContext({
        authorization: `Bearer ${token}`,
      });

      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
      await expect(guard.canActivate(ctx)).rejects.toThrow('Token has been revoked');
    });

    it('allows request when jti is NOT revoked', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);

      (authService.validateToken as jest.Mock).mockResolvedValue({
        userId: 'u1',
        roles: ['user'],
        jti: 'valid-jti',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      (revocationService.isRevoked as jest.Mock).mockReturnValue(false);

      const token = await createHs256Token({ sub: 'u1', roles: ['user'] }, { jti: 'valid-jti' });
      const ctx = createMockExecutionContext({
        authorization: `Bearer ${token}`,
      });

      const result = await guard.canActivate(ctx);
      expect(result).toBe(true);
    });

    it('revocation check runs AFTER jwtVerify (tampered token with revoked jti gets signature error, not revocation error)', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);

      // AuthService rejects with signature error BEFORE revocation is checked
      (authService.validateToken as jest.Mock).mockRejectedValue(
        new UnauthorizedException('Invalid token signature'),
      );

      const token = await createHs256Token(
        { sub: 'u1', roles: ['user'] },
        { jti: 'revoked-but-tampered' },
      );
      const ctx = createMockExecutionContext({
        authorization: `Bearer ${token}`,
      });

      // Revocation service should NOT be called because auth failed first
      await expect(guard.canActivate(ctx)).rejects.toThrow('Invalid token signature');
      expect(revocationService.isRevoked).not.toHaveBeenCalled();
    });
  });

  describe('auth.invalid_token emission (Phase 6 D-14)', () => {
    let emitSpy: jest.SpyInstance;

    beforeEach(() => {
      emitSpy = jest.spyOn(events, 'emit');
    });

    it('emits on missing Authorization header (no userId)', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      const ctx = createMockExecutionContext({ ip: '5.6.7.8' });

      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
      expect(emitSpy).toHaveBeenCalledWith(
        AUTH_INVALID_TOKEN,
        expect.objectContaining({
          type: AUTH_INVALID_TOKEN,
          ip: '5.6.7.8',
          userId: undefined,
        }),
      );
    });

    it('emits on bad scheme (Basic ...)', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      const ctx = createMockExecutionContext({
        authorization: 'Basic dXNlcjpwYXNz',
        ip: '5.6.7.8',
      });

      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
      expect(emitSpy).toHaveBeenCalledWith(
        AUTH_INVALID_TOKEN,
        expect.objectContaining({ type: AUTH_INVALID_TOKEN, ip: '5.6.7.8' }),
      );
    });

    it('emits on validateToken throw (no userId in payload)', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      (authService.validateToken as jest.Mock).mockRejectedValueOnce(
        new UnauthorizedException('Token expired'),
      );
      const ctx = createMockExecutionContext({
        authorization: 'Bearer x.y.z',
      });

      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
      expect(emitSpy).toHaveBeenCalledWith(
        AUTH_INVALID_TOKEN,
        expect.objectContaining({
          type: AUTH_INVALID_TOKEN,
          userId: undefined,
        }),
      );
    });

    it('emits on revocation hit (with userId)', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      (authService.validateToken as jest.Mock).mockResolvedValueOnce({
        userId: '42',
        roles: ['user'],
        jti: 'jti-revoked',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      (revocationService.isRevoked as jest.Mock).mockReturnValueOnce(true);
      const ctx = createMockExecutionContext({
        authorization: 'Bearer x.y.z',
      });

      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
      expect(emitSpy).toHaveBeenCalledWith(
        AUTH_INVALID_TOKEN,
        expect.objectContaining({
          type: AUTH_INVALID_TOKEN,
          userId: '42',
        }),
      );
    });

    it('emits with ja4h when (req as any)["x-ja4h"] is set', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      const ctx = createMockExecutionContext({ ja4h: 'jh-fp-123' });

      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
      expect(emitSpy).toHaveBeenCalledWith(
        AUTH_INVALID_TOKEN,
        expect.objectContaining({ ja4h: 'jh-fp-123' }),
      );
    });

    it('does NOT emit on successful auth', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      (authService.validateToken as jest.Mock).mockResolvedValueOnce({
        userId: '42',
        roles: ['user'],
        jti: 'jti-ok',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      (revocationService.isRevoked as jest.Mock).mockReturnValueOnce(false);
      const ctx = createMockExecutionContext({
        authorization: 'Bearer x.y.z',
      });

      await expect(guard.canActivate(ctx)).resolves.toBe(true);
      expect(emitSpy).not.toHaveBeenCalled();
    });

    it('does NOT emit on @Public() route', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(true);
      const ctx = createMockExecutionContext();

      await expect(guard.canActivate(ctx)).resolves.toBe(true);
      expect(emitSpy).not.toHaveBeenCalled();
    });

    it('payload always contains type, ip, ts (ThreatSignalPayload shape)', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      const ctx = createMockExecutionContext({ ip: '9.9.9.9' });

      await expect(guard.canActivate(ctx)).rejects.toThrow();
      const [, payload] = emitSpy.mock.calls[0];
      expect(payload).toEqual(
        expect.objectContaining({
          type: AUTH_INVALID_TOKEN,
          ip: '9.9.9.9',
          ts: expect.any(Number),
        }),
      );
    });
  });
});
