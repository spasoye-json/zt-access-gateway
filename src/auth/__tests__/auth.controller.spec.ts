import { Test } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { EventEmitter2, EventEmitterModule } from '@nestjs/event-emitter';
import { AuthController } from '../auth.controller';
import { TokenRevocationService } from '../token-revocation.service';
import { JwtAuthGuard } from '../jwt-auth.guard';
import { AUTH_TOKEN_REVOKED } from '../../metrics/metrics-events';

/**
 * AuthController unit tests -- TDD RED phase.
 * Tests will fail on import until auth.controller.ts is created in Wave 2.
 *
 * Coverage: TREV-03, D-07
 */
describe('AuthController', () => {
  let controller: AuthController;
  let revocationService: Partial<TokenRevocationService>;

  beforeEach(async () => {
    revocationService = {
      revoke: jest.fn(),
      isRevoked: jest.fn().mockReturnValue(false),
      getEntry: jest.fn().mockReturnValue(undefined),
      size: jest.fn().mockReturnValue(0),
    };

    // Phase 10 D-02: APP_GUARD removed; JwtAuthGuard now route-level via
    // @UseGuards on AuthController.revoke. Override the guard so DI doesn't
    // pull in AuthService/EventEmitter — these unit tests bypass the pipeline
    // and call controller.revoke() directly.
    const module = await Test.createTestingModule({
      imports: [EventEmitterModule.forRoot()],
      controllers: [AuthController],
      providers: [
        {
          provide: TokenRevocationService,
          useValue: revocationService,
        },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get(AuthController);
  });

  describe('POST /auth/revoke (TREV-03, D-07)', () => {
    it('revokes own token (userId matches request.user.userId)', () => {
      const dto = { jti: 'my-token-jti', exp: Math.floor(Date.now() / 1000) + 3600 };
      const req = {
        user: { userId: 'user-1', roles: ['user'] },
      } as unknown as Request;

      // Calling user-1 to revoke their own token
      const result = controller.revoke(dto, req);

      expect(revocationService.revoke).toHaveBeenCalledWith(
        'my-token-jti',
        expect.any(Number),
        'user-1',
      );
      expect(result).toEqual({ message: 'Token revoked' });
    });

    it('admin revokes any token regardless of userId', () => {
      // Revoke another user's token as admin
      (revocationService.getEntry as jest.Mock).mockReturnValue({
        expiresAt: Date.now() + 3600_000,
        userId: 'other-user',
      });

      const dto = { jti: 'other-user-jti', exp: Math.floor(Date.now() / 1000) + 3600 };
      const req = {
        user: { userId: 'admin-1', roles: ['admin'] },
      } as unknown as Request;

      const result = controller.revoke(dto, req);

      expect(revocationService.revoke).toHaveBeenCalledWith(
        'other-user-jti',
        expect.any(Number),
        'admin-1',
      );
      expect(result).toEqual({ message: 'Token revoked' });
    });

    it('rejects non-admin revoking another user token with 403 ForbiddenException', () => {
      // An existing revocation entry for a different user
      (revocationService.getEntry as jest.Mock).mockReturnValue({
        expiresAt: Date.now() + 3600_000,
        userId: 'other-user',
      });

      const dto = { jti: 'other-user-jti', exp: Math.floor(Date.now() / 1000) + 3600 };
      const req = {
        user: { userId: 'attacker', roles: ['user'] },
      } as unknown as Request;

      // Non-admin trying to revoke someone else's token should be forbidden
      expect(() => controller.revoke(dto, req)).toThrow(
        ForbiddenException,
      );
    });

    it('returns { message: "Token revoked" } on success', () => {
      const dto = { jti: 'jti-success', exp: Math.floor(Date.now() / 1000) + 3600 };
      const req = {
        user: { userId: 'user-1', roles: ['user'] },
      } as unknown as Request;

      const result = controller.revoke(dto, req);
      expect(result).toEqual({ message: 'Token revoked' });
    });
  });

  describe('Phase 14 Plan 01 — emits AUTH_TOKEN_REVOKED (SC-1)', () => {
    it('emits on successful revoke', () => {
      const localRevocationService = {
        revoke: jest.fn(),
        getEntry: jest.fn(),
      } as unknown as TokenRevocationService;
      const events = new EventEmitter2();
      const listener = jest.fn();
      events.on(AUTH_TOKEN_REVOKED, listener);
      const localController = new AuthController(localRevocationService, events);

      const result = localController.revoke(
        { jti: 'jti-1', exp: Math.floor(Date.now() / 1000) + 60 },
        { user: { userId: 'u-1', roles: ['user'] } } as never,
      );

      expect(result).toEqual({ message: 'Token revoked' });
      expect(listener).toHaveBeenCalledTimes(1);
    });

    it('does NOT emit on 403 ownership failure', () => {
      const localRevocationService = {
        revoke: jest.fn(),
        getEntry: jest.fn().mockReturnValue({ userId: 'someone-else' }),
      } as unknown as TokenRevocationService;
      const events = new EventEmitter2();
      const listener = jest.fn();
      events.on(AUTH_TOKEN_REVOKED, listener);
      const localController = new AuthController(localRevocationService, events);

      expect(() =>
        localController.revoke(
          { jti: 'jti-1', exp: Math.floor(Date.now() / 1000) + 60 },
          { user: { userId: 'u-1', roles: ['user'] } } as never,
        ),
      ).toThrow(ForbiddenException);

      expect(listener).not.toHaveBeenCalled();
      expect(localRevocationService.revoke).not.toHaveBeenCalled();
    });
  });
});
