import { RevocationStage } from '../revocation.stage';
import type { StageContext } from '../../stage-context';
import type { TokenRevocationService } from '../../../../auth/token-revocation.service';
import type { AuditService } from '../../../../audit/audit.service';
import type { MetricsService } from '../../../../metrics/metrics.service';
import type { UserClaims } from '../../../../auth/interfaces/user-claims.interface';

function makeClaims(overrides: Partial<UserClaims> = {}): UserClaims {
  return {
    userId: 'u1',
    roles: ['user'],
    jti: 'jti-1',
    exp: 9_999_999_999,
    deviceId: 'd1',
    ...overrides,
  };
}

function makeCtx(
  claims?: UserClaims,
  headers: Record<string, unknown> = {},
  method = 'GET',
): StageContext {
  return {
    req: {
      method,
      headers,
      ip: '10.0.0.1',
      socket: { remoteAddress: '10.0.0.1' },
    },
    requestId: 'req-1',
    reqPath: '/users/1',
    ja4h: 'ja4h-fp',
    claims,
  } as unknown as StageContext;
}

function build(): {
  stage: RevocationStage;
  revocation: jest.Mocked<TokenRevocationService>;
  audit: jest.Mocked<AuditService>;
  metrics: jest.Mocked<MetricsService>;
} {
  const revocation = {
    isRevoked: jest.fn().mockReturnValue(false),
  } as unknown as jest.Mocked<TokenRevocationService>;
  const audit = {
    log: jest.fn().mockResolvedValue(undefined),
  } as unknown as jest.Mocked<AuditService>;
  const metrics = {
    incrementAuditFailure: jest.fn(),
  } as unknown as jest.Mocked<MetricsService>;
  const stage = new RevocationStage(revocation, audit, metrics);
  return { stage, revocation, audit, metrics };
}

describe('RevocationStage', () => {
  it('id is "revocation"', () => {
    expect(build().stage.id).toBe('revocation');
  });

  it('no claims on ctx → continue (public/bypassed paths never reach revocation logic)', async () => {
    const { stage, revocation, audit } = build();
    const out = await stage.run(makeCtx(undefined));
    expect(out).toEqual({ kind: 'continue' });
    expect(revocation.isRevoked).not.toHaveBeenCalled();
    expect(audit.log).not.toHaveBeenCalled();
  });

  it('claims with non-revoked jti → continue, no audit, no short-circuit', async () => {
    const { stage, revocation, audit } = build();
    revocation.isRevoked.mockReturnValue(false);
    const out = await stage.run(makeCtx(makeClaims({ jti: 'jti-fresh' })));
    expect(out).toEqual({ kind: 'continue' });
    expect(revocation.isRevoked).toHaveBeenCalledWith('jti-fresh');
    expect(audit.log).not.toHaveBeenCalled();
  });

  it('revoked jti → short-circuit 401 token_revoked with requestId', async () => {
    const { stage, revocation } = build();
    revocation.isRevoked.mockReturnValue(true);
    const out = await stage.run(makeCtx(makeClaims({ jti: 'jti-blocked' })));
    expect(out).toEqual({
      kind: 'short-circuit',
      status: 401,
      body: { error: 'token_revoked', requestId: 'req-1' },
    });
  });

  it('revoked jti → audit.log called once with decision=deny + eventType=REVOCATION_BLOCKED before short-circuit', async () => {
    const { stage, revocation, audit } = build();
    revocation.isRevoked.mockReturnValue(true);
    await stage.run(makeCtx(makeClaims({ userId: 'alice', jti: 'jti-blocked' }), {}, 'POST'));
    expect(audit.log).toHaveBeenCalledTimes(1);
    const entry = audit.log.mock.calls[0][0];
    expect(entry).toEqual(
      expect.objectContaining({
        userId: 'alice',
        resource: '/users/1',
        action: 'POST',
        decision: 'deny',
        eventType: 'REVOCATION_BLOCKED',
        requestId: 'req-1',
        ja4hFingerprint: 'ja4h-fp',
        ipAddress: '10.0.0.1',
      }),
    );
  });
});
