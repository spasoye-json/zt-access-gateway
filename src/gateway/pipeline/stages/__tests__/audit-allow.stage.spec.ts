import { AuditAllowStage } from '../audit-allow.stage';
import type { StageContext } from '../../stage-context';
import type { AuditService } from '../../../../audit/audit.service';
import type { MetricsService } from '../../../../metrics/metrics.service';
import { AuditExhaustedException } from '../../../../audit/audit-exhausted.exception';

function build(): {
  stage: AuditAllowStage;
  audit: jest.Mocked<AuditService>;
  metrics: jest.Mocked<MetricsService>;
} {
  const audit = { log: jest.fn() } as unknown as jest.Mocked<AuditService>;
  const metrics = {
    observeAuditWalDuration: jest.fn(),
  } as unknown as jest.Mocked<MetricsService>;
  return { stage: new AuditAllowStage(audit, metrics), audit, metrics };
}

function makeCtx(): StageContext {
  return {
    req: { method: 'GET', headers: {}, ip: '1.1.1.1', socket: { remoteAddress: '1.1.1.1' } },
    claims: { userId: 'u1', roles: ['user'], jti: 'j', exp: 9, deviceId: 'd1' },
    requestId: 'req-1',
    reqPath: '/users/1',
    ja4h: 'ja4h',
    trustScore: 0.2,
  } as unknown as StageContext;
}

describe('AuditAllowStage', () => {
  it('id is "audit_allow"', () => {
    expect(build().stage.id).toBe('audit_allow');
  });

  it('success → audit.log called with allow entry + observeAuditWalDuration called + continue', async () => {
    const { stage, audit, metrics } = build();
    audit.log.mockResolvedValue(undefined);
    const out = await stage.run(makeCtx());
    expect(out).toEqual({ kind: 'continue' });
    expect(audit.log).toHaveBeenCalledWith(
      expect.objectContaining({
        decision: 'allow',
        userId: 'u1',
        resource: '/users/1',
        action: 'GET',
        trustScore: 0.2,
        requestId: 'req-1',
      }),
    );
    expect(metrics.observeAuditWalDuration).toHaveBeenCalledTimes(1);
  });

  it('AuditExhaustedException → rethrow; observeAuditWalDuration NOT called', async () => {
    const { stage, audit, metrics } = build();
    audit.log.mockRejectedValue(new AuditExhaustedException('wal full'));
    await expect(stage.run(makeCtx())).rejects.toBeInstanceOf(AuditExhaustedException);
    expect(metrics.observeAuditWalDuration).not.toHaveBeenCalled();
  });
});
