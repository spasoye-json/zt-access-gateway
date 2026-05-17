import { Test } from '@nestjs/testing';
import type { Request } from 'express';
import { DemoMfaController } from '../demo-mfa.controller';
import { MfaChallenger } from '../../mfa/mfa-challenger.service';
import { JwtAuthGuard } from '../../auth/jwt-auth.guard';
import type { UserClaims } from '../../auth/interfaces/user-claims.interface';

function buildRequest(opts: {
  user: Partial<UserClaims>;
  ip?: string;
  deviceId?: string;
}): Request {
  return {
    user: opts.user as UserClaims,
    headers: {
      'x-forwarded-for': opts.ip ?? '10.0.0.1',
      ...(opts.deviceId ? { 'x-device-id': opts.deviceId } : {}),
    },
    socket: { remoteAddress: '127.0.0.1' },
  } as unknown as Request;
}

describe('DemoMfaController', () => {
  let controller: DemoMfaController;
  let challenger: { mintDemoMfaToken: jest.Mock };

  beforeEach(async () => {
    challenger = {
      mintDemoMfaToken: jest
        .fn()
        .mockResolvedValue({ token: 'minted.jwt.value', expiresAt: 1_700_000_000_000 }),
    };

    const module = await Test.createTestingModule({
      controllers: [DemoMfaController],
      providers: [{ provide: MfaChallenger, useValue: challenger }],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get(DemoMfaController);
  });

  it('returns { mfaToken, expiresAt } shaped by MfaChallenger.mintDemoMfaToken', async () => {
    const req = buildRequest({
      user: { userId: 'alice', roles: ['user'] },
      ip: '10.0.0.5',
      deviceId: 'device-A',
    });

    const result = await controller.mint(req);

    expect(result).toEqual({ mfaToken: 'minted.jwt.value', expiresAt: 1_700_000_000_000 });
  });

  it('binds the minted token to the authenticated user, request IP, and device id', async () => {
    const req = buildRequest({
      user: { userId: 'alice', roles: ['user'] },
      ip: '10.0.0.5',
      deviceId: 'device-A',
    });

    await controller.mint(req);

    expect(challenger.mintDemoMfaToken).toHaveBeenCalledWith({
      userId: 'alice',
      deviceId: 'device-A',
      ip: '10.0.0.5',
    });
  });

  it('falls back to empty deviceId when x-device-id header is absent', async () => {
    const req = buildRequest({ user: { userId: 'bob', roles: ['user'] } });

    await controller.mint(req);

    expect(challenger.mintDemoMfaToken).toHaveBeenCalledWith({
      userId: 'bob',
      deviceId: '',
      ip: '10.0.0.1',
    });
  });
});
