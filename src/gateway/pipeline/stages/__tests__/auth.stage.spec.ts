import { AuthStage } from '../auth.stage';
import { GATEWAY_VALIDATED } from '../../../../auth/gateway-validated.symbol';
import { AUTH_INVALID_TOKEN } from '../../../../policy/policy-events';
import type { StageContext } from '../../stage-context';
import type { AuthService } from '../../../../auth/auth.service';
import type { AuditService } from '../../../../audit/audit.service';
import type { MetricsService } from '../../../../metrics/metrics.service';
import type { TypedEvents } from '../../../../shared/typed-events';

function makeCtx(headers: Record<string, unknown> = {}, method = 'GET'): StageContext {
  return {
    req: {
      method,
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
  audit: jest.Mocked<AuditService>;
  metrics: jest.Mocked<MetricsService>;
  events: { emit: jest.Mock };
} {
  const auth = { authenticate: jest.fn() } as unknown as jest.Mocked<AuthService>;
  const audit = {
    log: jest.fn().mockResolvedValue(undefined),
  } as unknown as jest.Mocked<AuditService>;
  const metrics = {
    incrementAuditFailure: jest.fn(),
  } as unknown as jest.Mocked<MetricsService>;
  const events = { emit: jest.fn() };
  const stage = new AuthStage(auth, audit, metrics, events as unknown as TypedEvents);
  return { stage, auth, audit, metrics, events };
}

describe('AuthStage', () => {
  it('id is "auth"', () => {
    expect(build().stage.id).toBe('auth');
  });

  it('outcome ok → sets ctx.claims, assigns plain claims to req.user, sets GATEWAY_VALIDATED, continues', async () => {
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
    expect(req.user).toEqual(claims);
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

  it('authenticate throws → propagates, no emit', async () => {
    const { stage, auth, events } = build();
    auth.authenticate.mockRejectedValue(new Error('db down'));
    await expect(stage.run(makeCtx({ authorization: 'Bearer abc' }))).rejects.toThrow('db down');
    expect(events.emit).not.toHaveBeenCalled();
  });

  describe('audit-on-deny (Slice C, #4)', () => {
    it('outcome invalid (missing) → audit.log called once with decision=deny before short-circuit', async () => {
      const { stage, auth, audit } = build();
      auth.authenticate.mockResolvedValue({ kind: 'invalid', reason: 'missing' });
      await stage.run(makeCtx({}, 'GET'));
      expect(audit.log).toHaveBeenCalledTimes(1);
      const entry = audit.log.mock.calls[0][0];
      expect(entry).toEqual(
        expect.objectContaining({
          decision: 'deny',
          resource: '/users/1',
          action: 'GET',
          requestId: 'req-1',
          ja4hFingerprint: 'ja4h-fp',
          ipAddress: '10.0.0.1',
        }),
      );
      // userId is required by the AuditEntry interface; anonymous on auth failure.
      expect(entry.userId).toBe('anonymous');
    });

    it('outcome invalid (token) → audit.log called with deny', async () => {
      const { stage, auth, audit } = build();
      auth.authenticate.mockResolvedValue({ kind: 'invalid', reason: 'token', message: 'expired' });
      await stage.run(makeCtx({ authorization: 'Bearer abc' }));
      expect(audit.log).toHaveBeenCalledTimes(1);
      expect(audit.log.mock.calls[0][0].decision).toBe('deny');
    });

    it('outcome ok → audit.log NOT called', async () => {
      const { stage, auth, audit } = build();
      auth.authenticate.mockResolvedValue({
        kind: 'ok',
        claims: { userId: 'u1', roles: ['user'], jti: 'j1', exp: 9, deviceId: 'd1' },
      });
      await stage.run(makeCtx({ authorization: 'Bearer abc' }));
      expect(audit.log).not.toHaveBeenCalled();
    });
  });
});
