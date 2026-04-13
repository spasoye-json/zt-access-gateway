import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtAuthGuard } from '../jwt-auth.guard';
import { AuthService } from '../auth.service';
import { TokenRevocationService } from '../token-revocation.service';
import { IS_PUBLIC_KEY } from '../../shared/public.decorator';
import {
  TEST_HS256_SECRET,
  createHs256Token,
} from './test-keys';

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

  function createMockExecutionContext(overrides?: {
    authorization?: string;
    isPublic?: boolean;
    roles?: string[];
  }): ExecutionContext {
    const request = {
      headers: {
        ...(overrides?.authorization !== undefined
          ? { authorization: overrides.authorization }
          : {}),
      },
      user: undefined as unknown,
    };

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
      switchToRpc: () => ({} as ReturnType<ExecutionContext['switchToRpc']>),
      switchToWs: () => ({} as ReturnType<ExecutionContext['switchToWs']>),
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

    guard = new JwtAuthGuard(
      reflector,
      authService as AuthService,
      revocationService as TokenRevocationService,
    );
  });

  describe('@Public() bypass (AUTH-07)', () => {
    it('returns true without validating token when route is @Public()', async () => {
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValue(true);

      const ctx = createMockExecutionContext();
      const result = await guard.canActivate(ctx);

      expect(result).toBe(true);
      expect(authService.validateToken).not.toHaveBeenCalled();
    });

    it('proceeds to validate token when route is NOT @Public()', async () => {
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValue(false);

      const token = await createHs256Token(
        { sub: 'u1', roles: ['user'] },
        { jti: 'jti-1' },
      );
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

  describe('Bearer extraction (AUTH-06)', () => {
    it('extracts token from Authorization: Bearer <token> header', async () => {
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValue(false);

      const token = await createHs256Token(
        { sub: 'u1', roles: ['user'] },
        { jti: 'jti-extract' },
      );
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
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValue(false);

      const ctx = createMockExecutionContext();

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('throws UnauthorizedException when Authorization header not Bearer scheme', async () => {
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValue(false);

      const ctx = createMockExecutionContext({
        authorization: 'Basic dXNlcjpwYXNz',
      });

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  describe('UserClaims attachment (AUTH-06)', () => {
    it('attaches validated UserClaims to request.user', async () => {
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValue(false);

      const expectedClaims = {
        userId: 'u1',
        roles: ['user'],
        jti: 'jti-attach',
        exp: Math.floor(Date.now() / 1000) + 3600,
      };
      (authService.validateToken as jest.Mock).mockResolvedValue(
        expectedClaims,
      );

      const token = await createHs256Token(
        { sub: 'u1', roles: ['user'] },
        { jti: 'jti-attach' },
      );
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
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValue(false);

      const claims = {
        userId: 'u1',
        roles: ['user'],
        jti: 'revoked-jti',
        exp: Math.floor(Date.now() / 1000) + 3600,
      };
      (authService.validateToken as jest.Mock).mockResolvedValue(claims);
      (revocationService.isRevoked as jest.Mock).mockReturnValue(true);

      const token = await createHs256Token(
        { sub: 'u1', roles: ['user'] },
        { jti: 'revoked-jti' },
      );
      const ctx = createMockExecutionContext({
        authorization: `Bearer ${token}`,
      });

      await expect(guard.canActivate(ctx)).rejects.toThrow(
        UnauthorizedException,
      );
      await expect(guard.canActivate(ctx)).rejects.toThrow(
        'Token has been revoked',
      );
    });

    it('allows request when jti is NOT revoked', async () => {
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValue(false);

      (authService.validateToken as jest.Mock).mockResolvedValue({
        userId: 'u1',
        roles: ['user'],
        jti: 'valid-jti',
        exp: Math.floor(Date.now() / 1000) + 3600,
      });
      (revocationService.isRevoked as jest.Mock).mockReturnValue(false);

      const token = await createHs256Token(
        { sub: 'u1', roles: ['user'] },
        { jti: 'valid-jti' },
      );
      const ctx = createMockExecutionContext({
        authorization: `Bearer ${token}`,
      });

      const result = await guard.canActivate(ctx);
      expect(result).toBe(true);
    });

    it('revocation check runs AFTER jwtVerify (tampered token with revoked jti gets signature error, not revocation error)', async () => {
      jest
        .spyOn(reflector, 'getAllAndOverride')
        .mockReturnValue(false);

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
      await expect(guard.canActivate(ctx)).rejects.toThrow(
        'Invalid token signature',
      );
      expect(revocationService.isRevoked).not.toHaveBeenCalled();
    });
  });
});
