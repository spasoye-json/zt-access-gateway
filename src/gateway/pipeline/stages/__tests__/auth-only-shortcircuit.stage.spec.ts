import { AuthOnlyShortCircuitStage } from '../auth-only-shortcircuit.stage';
import type { StageContext } from '../../stage-context';
import type { AuditService } from '../../../../audit/audit.service';
import type { MetricsService } from '../../../../metrics/metrics.service';

function build(): {
  stage: AuthOnlyShortCircuitStage;
  audit: jest.Mocked<AuditService>;
  metrics: jest.Mocked<MetricsService>;
} {
  const audit = { log: jest.fn().mockResolvedValue(undefined) } as unknown as jest.Mocked<AuditService>;
  const metrics = {
    incrementAuditFailure: jest.fn(),
  } as unknown as jest.Mocked<MetricsService>;
  return { stage: new AuthOnlyShortCircuitStage(audit, metrics), audit, metrics };
}

function makeCtx(reqPath: string): StageContext {
  return {
    req: { method: 'POST', headers: {}, ip: '10.0.0.1', socket: { remoteAddress: '10.0.0.1' } },
    claims: { userId: 'u1', roles: ['user'], jti: 'j', exp: 9, deviceId: 'd1' },
    requestId: 'req-1',
    reqPath,
    ja4h: 'ja4h-1',
  } as unknown as StageContext;
}

describe('AuthOnlyShortCircuitStage', () => {
  it('id is "auth_only"', () => {
    expect(build().stage.id).toBe('auth_only');
  });

  it('non auth-only path → continue (no audit call)', async () => {
    const { stage, audit } = build();
    const out = await stage.run(makeCtx('/users/1'));
    expect(out).toEqual({ kind: 'continue' });
    expect(audit.log).not.toHaveBeenCalled();
  });

  it('auth-only exact path → audit allow + bypass; trustScore omitted', async () => {
    const { stage, audit } = build();
    const out = await stage.run(makeCtx('/auth/revoke'));
    expect(out).toEqual({ kind: 'bypass' });
    expect(audit.log).toHaveBeenCalledTimes(1);
    const entry = audit.log.mock.calls[0][0];
    expect(entry.decision).toBe('allow');
    expect(entry.userId).toBe('u1');
    expect(entry.resource).toBe('/auth/revoke');
    expect(entry.trustScore).toBeUndefined();
  });

  it('auth-only prefix path → bypass', async () => {
    const { stage } = build();
    const out = await stage.run(makeCtx('/mfa/admin/enrollment/some-user'));
    expect(out).toEqual({ kind: 'bypass' });
  });

  it('audit timeout → bypass still emitted; incrementAuditFailure called', async () => {
    const { stage, audit, metrics } = build();
    audit.log.mockReturnValue(new Promise(() => {})); // never resolves
    const out = await stage.run(makeCtx('/auth/revoke'));
    expect(out).toEqual({ kind: 'bypass' });
    expect(metrics.incrementAuditFailure).toHaveBeenCalledTimes(1);
  });
});
