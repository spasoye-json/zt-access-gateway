import { Test } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { AuthController } from '../auth.controller';
import { TokenRevocationService } from '../token-revocation.service';

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

    const module = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: TokenRevocationService,
          useValue: revocationService,
        },
      ],
    }).compile();

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
});
