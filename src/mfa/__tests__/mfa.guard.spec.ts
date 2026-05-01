import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { MfaGuard } from '../mfa.guard';
import { MfaService } from '../mfa.service';

// Helper to build a mock ExecutionContext
function mockContext(overrides: {
  method?: string;
  headers?: Record<string, string>;
  user?: { userId: string; deviceId: string };
  handler?: object;
  klass?: object;
}): ExecutionContext {
  const req = {
    method: overrides.method ?? 'GET',
    headers: overrides.headers ?? {},
    user: overrides.user ?? { userId: 'u1', deviceId: 'd1' },
    socket: { remoteAddress: '127.0.0.1' },
    ip: '10.0.0.1',
  };
  return {
    switchToHttp: () => ({ getRequest: () => req }),
    getHandler: () => overrides.handler ?? {},
    getClass: () => overrides.klass ?? {},
  } as unknown as ExecutionContext;
}

describe('MfaGuard', () => {
  let guard: MfaGuard;
  let mfaService: jest.Mocked<Pick<MfaService, 'validateMfaToken'>>;
  let reflector: jest.Mocked<Reflector>;

  beforeEach(() => {
    mfaService = { validateMfaToken: jest.fn() };
    reflector = { getAllAndOverride: jest.fn().mockReturnValue(false) } as unknown as jest.Mocked<Reflector>;
    guard = new MfaGuard(reflector, mfaService as unknown as MfaService);
  });

  it('passes through when @Public() is set on handler', async () => {
    reflector.getAllAndOverride.mockReturnValue(true);
    const ctx = mockContext({});
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
    expect(mfaService.validateMfaToken).not.toHaveBeenCalled();
  });

  it('throws UnauthorizedException({ error: mfa_required }) when X-MFA-Token header absent', async () => {
    const ctx = mockContext({ headers: {} });
    await expect(guard.canActivate(ctx)).rejects.toMatchObject(
      new UnauthorizedException({ error: 'mfa_required' }),
    );
  });

  it('attaches result.claims to request.mfaToken and returns true on valid token', async () => {
    const claims = { sub: 'u1', jti: 'j1', deviceId: 'd1', fpHash: 'fp', typ: 'mfa' as const, iat: 0, exp: 9999999999 };
    mfaService.validateMfaToken.mockResolvedValue({ ok: true, claims });
    const ctx = mockContext({ headers: { 'x-mfa-token': 'sometoken' } });
    const result = await guard.canActivate(ctx);
    expect(result).toBe(true);
    expect((ctx.switchToHttp().getRequest() as Record<string, unknown>).mfaToken).toEqual(claims);
  });

  it('throws UnauthorizedException({ error: mfa_invalid, reason: fingerprint_mismatch })', async () => {
    mfaService.validateMfaToken.mockResolvedValue({ ok: false, reason: 'fingerprint_mismatch' });
    const ctx = mockContext({ headers: { 'x-mfa-token': 'sometoken' } });
    await expect(guard.canActivate(ctx)).rejects.toMatchObject(
      new UnauthorizedException({ error: 'mfa_invalid', reason: 'fingerprint_mismatch' }),
    );
  });

  it('throws UnauthorizedException({ error: mfa_invalid, reason: expired })', async () => {
    mfaService.validateMfaToken.mockResolvedValue({ ok: false, reason: 'expired' });
    const ctx = mockContext({ headers: { 'x-mfa-token': 'sometoken' } });
    await expect(guard.canActivate(ctx)).rejects.toMatchObject(
      new UnauthorizedException({ error: 'mfa_invalid', reason: 'expired' }),
    );
  });

  it('throws UnauthorizedException({ error: mfa_invalid, reason: revoked })', async () => {
    mfaService.validateMfaToken.mockResolvedValue({ ok: false, reason: 'revoked' });
    const ctx = mockContext({ headers: { 'x-mfa-token': 'sometoken' } });
    await expect(guard.canActivate(ctx)).rejects.toMatchObject(
      new UnauthorizedException({ error: 'mfa_invalid', reason: 'revoked' }),
    );
  });
});
