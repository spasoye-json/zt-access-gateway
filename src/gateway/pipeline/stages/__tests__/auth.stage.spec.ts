import { AuthStage } from '../auth.stage';
import { GATEWAY_VALIDATED } from '../../../../auth/gateway-validated.symbol';
import { AUTH_INVALID_TOKEN } from '../../../../policy/policy-events';
import type { StageContext } from '../../stage-context';
import type { AuthService } from '../../../../auth/auth.service';
import type { TypedEvents } from '../../../../shared/typed-events';

function makeCtx(headers: Record<string, unknown> = {}): StageContext {
  return {
    req: {
      headers,
      ip: '10.0.0.1',
      socket: { remoteAddress: '10.0.0.1' },
      'x-ja4h': 'ja4h-fp',
    },
    requestId: 'req-1',
    reqPath: '/users/1',
    ja4h: 'ja4h-fp',
  } as unknown as StageContext;
}

function build(): {
  stage: AuthStage;
  auth: jest.Mocked<AuthService>;
  events: { emit: jest.Mock };
} {
  const auth = { authenticate: jest.fn() } as unknown as jest.Mocked<AuthService>;
  const events = { emit: jest.fn() };
  const stage = new AuthStage(auth, events as unknown as TypedEvents);
  return { stage, auth, events };
}

describe('AuthStage', () => {
  it('id is "auth"', () => {
    expect(build().stage.id).toBe('auth');
  });

  it('outcome ok → sets ctx.claims, brands req.user, sets GATEWAY_VALIDATED, continues', async () => {
    const { stage, auth } = build();
    const claims = { userId: 'u1', roles: ['user'], jti: 'j1', exp: 9, deviceId: 'd1' };
    auth.authenticate.mockResolvedValue({ kind: 'ok', claims });
    const ctx = makeCtx({ authorization: 'Bearer abc' });

    const out = await stage.run(ctx);

    expect(out).toEqual({ kind: 'continue' });
    expect(ctx.claims).toBe(claims);
    const req = ctx.req as unknown as Record<string | symbol, unknown> & {
      user?: Record<string, unknown>;
    };
    expect(req.user).toEqual({ ...claims, __authenticatedByGateway: true });
    expect(req[GATEWAY_VALIDATED]).toBe(true);
  });

  it.each(['missing', 'scheme'] as const)(
    'outcome invalid (%s) → 401 auth_required + emits AUTH_INVALID_TOKEN',
    async (reason) => {
      const { stage, auth, events } = build();
      auth.authenticate.mockResolvedValue({ kind: 'invalid', reason });
      const out = await stage.run(makeCtx({}));
      expect(out).toEqual({
        kind: 'short-circuit',
        status: 401,
        body: { error: 'auth_required', requestId: 'req-1' },
      });
      expect(events.emit).toHaveBeenCalledWith(
        AUTH_INVALID_TOKEN,
        expect.objectContaining({ type: AUTH_INVALID_TOKEN, ja4h: 'ja4h-fp' }),
      );
    },
  );

  it('outcome invalid (token) → 401 auth_invalid w/ message + emits', async () => {
    const { stage, auth, events } = build();
    auth.authenticate.mockResolvedValue({
      kind: 'invalid',
      reason: 'token',
      message: 'expired',
    });
    const out = await stage.run(makeCtx({ authorization: 'Bearer abc' }));
    expect(out).toEqual({
      kind: 'short-circuit',
      status: 401,
      body: { error: 'auth_invalid', message: 'expired', requestId: 'req-1' },
    });
    expect(events.emit).toHaveBeenCalledWith(
      AUTH_INVALID_TOKEN,
      expect.objectContaining({ type: AUTH_INVALID_TOKEN }),
    );
  });

  it('outcome revoked → 401 token_revoked, NO emit', async () => {
    const { stage, auth, events } = build();
    auth.authenticate.mockResolvedValue({ kind: 'revoked' });
    const out = await stage.run(makeCtx({ authorization: 'Bearer abc' }));
    expect(out).toEqual({
      kind: 'short-circuit',
      status: 401,
      body: { error: 'token_revoked', requestId: 'req-1' },
    });
    expect(events.emit).not.toHaveBeenCalled();
  });

  it('authenticate throws → propagates, no emit', async () => {
    const { stage, auth, events } = build();
    auth.authenticate.mockRejectedValue(new Error('db down'));
    await expect(stage.run(makeCtx({ authorization: 'Bearer abc' }))).rejects.toThrow('db down');
    expect(events.emit).not.toHaveBeenCalled();
  });
});
