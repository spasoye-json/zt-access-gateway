import { UnauthorizedException } from '@nestjs/common';
import { AuthStage } from '../auth.stage';
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
    },
    requestId: 'req-1',
    reqPath: '/users/1',
    ja4h: 'ja4h-fp',
  } as unknown as StageContext;
}

function build(): { stage: AuthStage; auth: jest.Mocked<AuthService>; events: { emit: jest.Mock } } {
  const auth = { validateToken: jest.fn() } as unknown as jest.Mocked<AuthService>;
  const events = { emit: jest.fn() };
  const stage = new AuthStage(auth, events as unknown as TypedEvents);
  return { stage, auth, events };
}

describe('AuthStage', () => {
  it('id is "auth"', () => {
    expect(build().stage.id).toBe('auth');
  });

  it('missing Authorization header → 401 auth_required + emits AUTH_INVALID_TOKEN', async () => {
    const { stage, events } = build();
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
  });

  it('non-string Authorization header → 401 auth_required', async () => {
    const { stage } = build();
    const out = await stage.run(makeCtx({ authorization: ['x'] }));
    expect((out as { kind: string; status: number }).status).toBe(401);
  });

  it('non-Bearer scheme → 401 auth_required + emits AUTH_INVALID_TOKEN', async () => {
    const { stage, events } = build();
    const out = await stage.run(makeCtx({ authorization: 'Basic xyz' }));
    expect((out as { status: number; body: { error: string } }).body.error).toBe('auth_required');
    expect(events.emit).toHaveBeenCalled();
  });

  it('empty token after Bearer → 401 auth_required', async () => {
    const { stage } = build();
    const out = await stage.run(makeCtx({ authorization: 'Bearer ' }));
    expect((out as { status: number }).status).toBe(401);
  });

  it('validateToken throws UnauthorizedException → 401 auth_invalid w/ message + emits', async () => {
    const { stage, auth, events } = build();
    auth.validateToken.mockRejectedValue(new UnauthorizedException('expired'));
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

  it('validateToken throws generic Error → rethrow (propagates)', async () => {
    const { stage, auth, events } = build();
    auth.validateToken.mockRejectedValue(new Error('db down'));
    await expect(stage.run(makeCtx({ authorization: 'Bearer abc' }))).rejects.toThrow(
      'db down',
    );
    expect(events.emit).not.toHaveBeenCalled();
  });

  it('success → ctx.claims set + continue', async () => {
    const { stage, auth } = build();
    const claims = { userId: 'u1', roles: ['user'], jti: 'j1', exp: 9, deviceId: 'd1' };
    auth.validateToken.mockResolvedValue(claims);
    const ctx = makeCtx({ authorization: 'Bearer abc' });
    const out = await stage.run(ctx);
    expect(out).toEqual({ kind: 'continue' });
    expect(ctx.claims).toBe(claims);
  });
});
