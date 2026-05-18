import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { TypedEvents } from '../../shared/typed-events';
import { JwtAuthGuard } from '../jwt-auth.guard';
import { AuthService } from '../auth.service';
import { GATEWAY_VALIDATED } from '../gateway-validated.symbol';
import { AUTH_INVALID_TOKEN } from '../../policy/policy-events';
import type { UserClaims } from '../interfaces/user-claims.interface';

/**
 * Issue #18 — JwtAuthGuard collapses onto AuthService.authenticate().
 *
 * Coverage:
 *   - @Public() bypass (AUTH-07)
 *   - GATEWAY_VALIDATED Symbol-brand bypass (sole gateway short-circuit)
 *   - Three AuthOutcome arms → exception + emit behaviour
 *   - Array-Authorization header → 401 + emit (WR-02 closure: no TypeError)
 */
describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;
  let reflector: Reflector;
  let authService: { authenticate: jest.Mock };
  let events: TypedEvents;
  let emitSpy: jest.SpyInstance;

  function makeClaims(overrides: Partial<UserClaims> = {}): UserClaims {
    return {
      userId: 'u1',
      roles: ['user'],
      jti: 'jti-1',
      exp: Math.floor(Date.now() / 1000) + 3600,
      deviceId: 'dev-1',
      ...overrides,
    };
  }

  function ctxFor(req: Record<string, unknown>): ExecutionContext {
    const handler = {} as () => void;
    const classRef = {} as () => void;
    return {
      switchToHttp: () => ({
        getRequest: () => req,
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

  function makeReq(
    overrides: {
      authorization?: string | string[];
      ip?: string;
      ja4h?: string;
      gatewayValidated?: boolean;
      user?: unknown;
    } = {},
  ): Record<string, unknown> {
    const ip = overrides.ip ?? '1.2.3.4';
    const headers: Record<string, unknown> = {};
    if (overrides.authorization !== undefined) headers.authorization = overrides.authorization;
    const req: Record<string, unknown> = {
      headers,
      ip,
      socket: { remoteAddress: ip },
    };
    if (overrides.user !== undefined) req.user = overrides.user;
    if (overrides.ja4h !== undefined) req['x-ja4h'] = overrides.ja4h;
    if (overrides.gatewayValidated === true) req[GATEWAY_VALIDATED as unknown as string] = true;
    return req;
  }

  beforeEach(() => {
    reflector = new Reflector();
    authService = { authenticate: jest.fn() };
    events = new TypedEvents(new EventEmitter2());
    emitSpy = jest.spyOn(events, 'emit');
    guard = new JwtAuthGuard(reflector, authService as unknown as AuthService, events);
  });

  describe('@Public() bypass (AUTH-07)', () => {
    it('returns true and does NOT call authenticate() when route is @Public()', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(true);
      const ctx = ctxFor(makeReq());

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(authService.authenticate).not.toHaveBeenCalled();
      expect(emitSpy).not.toHaveBeenCalled();
    });
  });

  describe('GATEWAY_VALIDATED Symbol bypass', () => {
    it('req[GATEWAY_VALIDATED]===true → true; authenticate() NOT called; no emit', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      const req = makeReq({ gatewayValidated: true });
      const ctx = ctxFor(req);

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(authService.authenticate).not.toHaveBeenCalled();
      expect(emitSpy).not.toHaveBeenCalled();
    });

    it('pre-populated req.user does NOT bypass — falls through to authenticate()', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      const claims = makeClaims({ userId: 'u-real', jti: 'jti-real' });
      authService.authenticate.mockResolvedValue({ kind: 'ok', claims });

      // Attacker-shaped UserClaims pre-populated on req.user; only the
      // Symbol-key gate bypasses, never a wire-deserialisable field.
      const ctx = ctxFor(
        makeReq({
          authorization: 'Bearer x.y.z',
          user: {
            userId: 'attacker',
            roles: ['admin'],
            jti: 'x',
            exp: 0,
            deviceId: 'd',
          },
        }),
      );

      await guard.canActivate(ctx);

      expect(authService.authenticate).toHaveBeenCalledTimes(1);
    });
  });

  describe('AuthOutcome → exception + emit mapping', () => {
    it('ok → true; assigns req.user; brands req with GATEWAY_VALIDATED; no emit', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      const claims = makeClaims();
      authService.authenticate.mockResolvedValue({ kind: 'ok', claims });

      const req = makeReq({ authorization: 'Bearer x.y.z' });
      const ctx = ctxFor(req);

      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(req.user).toEqual(claims);
      expect(req[GATEWAY_VALIDATED as unknown as string]).toBe(true);
      expect(emitSpy).not.toHaveBeenCalled();
    });

    it('invalid (token, with message) → UnauthorizedException(message) + emit', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      authService.authenticate.mockResolvedValue({
        kind: 'invalid',
        reason: 'token',
        message: 'Token has expired',
      });

      const ctx = ctxFor(makeReq({ authorization: 'Bearer x.y.z', ip: '5.6.7.8' }));

      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
      await expect(guard.canActivate(ctx)).rejects.toThrow('Token has expired');
      expect(emitSpy).toHaveBeenCalledWith(
        AUTH_INVALID_TOKEN,
        expect.objectContaining({ type: AUTH_INVALID_TOKEN, ip: '5.6.7.8' }),
      );
    });

    it('invalid (missing) → UnauthorizedException + emit', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      authService.authenticate.mockResolvedValue({
        kind: 'invalid',
        reason: 'missing',
      });

      const ctx = ctxFor(makeReq({ ip: '5.6.7.8' }));

      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
      expect(emitSpy).toHaveBeenCalledWith(
        AUTH_INVALID_TOKEN,
        expect.objectContaining({ type: AUTH_INVALID_TOKEN, ip: '5.6.7.8' }),
      );
    });

    it('invalid (scheme) → UnauthorizedException + emit', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      authService.authenticate.mockResolvedValue({
        kind: 'invalid',
        reason: 'scheme',
      });

      const ctx = ctxFor(makeReq({ authorization: 'Basic dXNlcjpwYXNz' }));

      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
      expect(emitSpy).toHaveBeenCalledWith(
        AUTH_INVALID_TOKEN,
        expect.objectContaining({ type: AUTH_INVALID_TOKEN }),
      );
    });

    it('propagates non-UnauthorizedException thrown by authenticate() (e.g., DB outage)', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      authService.authenticate.mockRejectedValue(new Error('jwks down'));

      const ctx = ctxFor(makeReq({ authorization: 'Bearer x.y.z' }));

      await expect(guard.canActivate(ctx)).rejects.toThrow('jwks down');
      expect(emitSpy).not.toHaveBeenCalled();
    });
  });

  describe('Array-valued Authorization header (WR-02 closure)', () => {
    it('duplicate Authorization headers → 401 + emit (no TypeError)', async () => {
      // The Symbol-keyed seam means the array is handled inside authenticate(),
      // which classifies it as invalid:missing. The guard maps to 401 + emit
      // exactly like any other invalid outcome — no foot-gun TypeError escape.
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      authService.authenticate.mockResolvedValue({
        kind: 'invalid',
        reason: 'missing',
      });

      const ctx = ctxFor(makeReq({ authorization: ['Bearer abc', 'Bearer def'], ip: '9.9.9.9' }));

      await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
      expect(emitSpy).toHaveBeenCalledWith(
        AUTH_INVALID_TOKEN,
        expect.objectContaining({ type: AUTH_INVALID_TOKEN, ip: '9.9.9.9' }),
      );
    });
  });

  describe('payload shape', () => {
    it('emitted payload carries type, ip, ts (ThreatSignalPayload shape)', async () => {
      jest.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);
      authService.authenticate.mockResolvedValue({
        kind: 'invalid',
        reason: 'missing',
      });

      const ctx = ctxFor(makeReq({ ip: '9.9.9.9', ja4h: 'jh-fp-1' }));

      await expect(guard.canActivate(ctx)).rejects.toThrow();
      const [, payload] = emitSpy.mock.calls[0];
      expect(payload).toEqual(
        expect.objectContaining({
          type: AUTH_INVALID_TOKEN,
          ip: '9.9.9.9',
          ja4h: 'jh-fp-1',
          ts: expect.any(Number),
        }),
      );
    });
  });
});
