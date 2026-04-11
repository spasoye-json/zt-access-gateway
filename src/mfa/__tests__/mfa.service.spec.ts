import { UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MfaService } from '../mfa.service';
import { MfaRepository } from '../mfa.repository';

describe('MfaService', () => {
  let service: MfaService;
  let config: Partial<ConfigService>;
  let repository: jest.Mocked<MfaRepository>;

  beforeEach(() => {
    config = {
      get: jest.fn().mockReturnValue(undefined),
    };

    repository = {
      createChallenge: jest.fn().mockResolvedValue(undefined),
      findChallenge: jest.fn(),
      markChallengeVerified: jest.fn().mockResolvedValue(undefined),
      deleteChallenge: jest.fn().mockResolvedValue(undefined),
      createToken: jest.fn().mockResolvedValue(undefined),
      findToken: jest.fn(),
      deleteToken: jest.fn().mockResolvedValue(undefined),
      cleanupExpired: jest.fn().mockResolvedValue(undefined),
      onModuleInit: jest.fn(),
      onModuleDestroy: jest.fn(),
    } as unknown as jest.Mocked<MfaRepository>;

    service = new MfaService(config as ConfigService, repository);
  });

  it('issues challenges and verifies MFA flow', async () => {
    repository.findChallenge.mockResolvedValue({
      challengeId: 'chal-abc',
      userId: 'user-1',
      code: '123456',
      expiresAt: new Date(Date.now() + 10000),
      verifiedAt: null,
      metadata: {},
    });

    const challenge = await service.initiateChallenge({
      userId: 'user-1',
      sessionId: 'session-1',
      method: 'GET',
      path: '/users',
      deviceId: 'device-1',
      ip: '10.0.0.1',
    });

    expect(repository.createChallenge).toHaveBeenCalledWith(
      expect.objectContaining({ challengeId: challenge.challengeId }),
    );

    const token = await service.verifyChallenge('user-1', 'chal-abc', '123456');
    expect(token.mfaToken).toMatch(/^mfa-/);
    expect(repository.createToken).toHaveBeenCalled();

    const createdToken = (repository.createToken as jest.Mock).mock.calls[0][0];
    repository.findToken.mockResolvedValue({
      token: createdToken.token,
      userId: createdToken.userId,
      challengeId: createdToken.challengeId,
      expiresAt: createdToken.expiresAt,
    });

    await expect(service.isTokenValid('user-1', createdToken.token)).resolves.toBe(true);
  });

  it('rejects invalid MFA codes', async () => {
    repository.findChallenge.mockResolvedValue({
      challengeId: 'chal-bad',
      userId: 'user-2',
      code: '999999',
      expiresAt: new Date(Date.now() + 10000),
      verifiedAt: null,
      metadata: {},
    });

    await expect(
      service.verifyChallenge('user-2', 'chal-bad', '000000'),
    ).rejects.toThrow(UnauthorizedException);
  });
});
