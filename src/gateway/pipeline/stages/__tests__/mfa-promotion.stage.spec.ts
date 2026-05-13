import { MfaPromotionStage } from '../mfa-promotion.stage';
import type { StageContext } from '../../stage-context';
import type { MfaChallenger } from '../../../../mfa/mfa-challenger.service';
import type { AuditService } from '../../../../audit/audit.service';
import type { MetricsService } from '../../../../metrics/metrics.service';
import type { PolicyDecision } from '../../../../policy/policy-decision';

function build(): {
  stage: MfaPromotionStage;
  mfa: jest.Mocked<MfaChallenger>;
  audit: jest.Mocked<AuditService>;
  metrics: jest.Mocked<MetricsService>;
} {
  const mfa = {
    validateMfaToken: jest.fn(),
    createChallenge: jest.fn(),
  } as unknown as jest.Mocked<MfaChallenger>;
  const audit = {
    log: jest.fn().mockResolvedValue(undefined),
  } as unknown as jest.Mocked<AuditService>;
  const metrics = {
    incrementMfaPromotion: jest.fn(),
    incrementRequest: jest.fn(),
    incrementAuditFailure: jest.fn(),
  } as unknown as jest.Mocked<MetricsService>;
  return { stage: new MfaPromotionStage(mfa, audit, metrics), mfa, audit, metrics };
}

function makeCtx(decision: PolicyDecision, headers: Record<string, string> = {}): StageContext {
  return {
    req: { method: 'POST', headers, ip: '1.1.1.1', socket: { remoteAddress: '1.1.1.1' } },
    claims: { userId: 'u1', roles: ['user'], jti: 'j', exp: 9, deviceId: 'd1' },
    requestId: 'req-1',
    reqPath: '/x',
    ja4h: 'ja4h',
    trustScore: 0.6,
    policyDecision: decision,
  } as unknown as StageContext;
}

describe('MfaPromotionStage', () => {
  it('id is "mfa_promotion"', () => {
    expect(build().stage.id).toBe('mfa_promotion');
  });

  it('ALLOW → continue (no metric, no audit)', async () => {
    const { stage, audit, metrics } = build();
    const out = await stage.run(
      makeCtx({ decision: 'ALLOW', reason: 'ok', score: 0.1, matchedSubject: 'user:u1' }),
    );
    expect(out).toEqual({ kind: 'continue' });
    expect(audit.log).not.toHaveBeenCalled();
    expect(metrics.incrementRequest).not.toHaveBeenCalled();
  });

  it('DENY → audit deny + incrementRequest(deny) + 403 policy_denied', async () => {
    const { stage, audit, metrics } = build();
    const out = await stage.run(makeCtx({ decision: 'DENY', reason: 'blacklist', score: 0.9 }));
    expect(out).toEqual({
      kind: 'short-circuit',
      status: 403,
      body: { error: 'policy_denied', reason: 'blacklist', requestId: 'req-1' },
    });
    expect(audit.log).toHaveBeenCalledWith(expect.objectContaining({ decision: 'deny' }));
    expect(metrics.incrementRequest).toHaveBeenCalledWith('deny');
  });

  it('CHALLENGE with valid X-MFA-Token → continue + incrementMfaPromotion(allow)', async () => {
    const { stage, mfa, metrics } = build();
    mfa.validateMfaToken.mockResolvedValue({ ok: true, claims: {} as never });
    const out = await stage.run(
      makeCtx({ decision: 'CHALLENGE', reason: 'mid', score: 0.6 }, { 'x-mfa-token': 'tok' }),
    );
    expect(out).toEqual({ kind: 'continue' });
    expect(metrics.incrementMfaPromotion).toHaveBeenCalledWith('allow');
  });

  it('CHALLENGE without X-MFA-Token → 401 mfa_required + WWW-Authenticate header', async () => {
    const { stage, mfa, metrics } = build();
    mfa.createChallenge.mockResolvedValue({
      ok: true,
      challengeId: 'cid-1',
      expiresAt: 1700000000000,
    });
    const out = await stage.run(makeCtx({ decision: 'CHALLENGE', reason: 'mid', score: 0.6 }));
    expect(out).toEqual({
      kind: 'short-circuit',
      status: 401,
      body: {
        error: 'mfa_required',
        challengeId: 'cid-1',
        verifyEndpoint: '/mfa/verify',
        expiresAt: new Date(1700000000000).toISOString(),
        requestId: 'req-1',
      },
      headers: {
        'WWW-Authenticate': 'MFA realm="gateway", challengeId="cid-1"',
        'X-MFA-Challenge': 'cid-1',
      },
    });
    expect(metrics.incrementMfaPromotion).toHaveBeenCalledWith('reject');
    expect(metrics.incrementRequest).toHaveBeenCalledWith('challenge');
  });

  it('CHALLENGE with invalid X-MFA-Token → 401 mfa_required (same path as no-token)', async () => {
    const { stage, mfa } = build();
    mfa.validateMfaToken.mockResolvedValue({ ok: false, reason: 'fingerprint_mismatch' } as never);
    mfa.createChallenge.mockResolvedValue({
      ok: true,
      challengeId: 'cid-2',
      expiresAt: 1700000000000,
    });
    const out = await stage.run(
      makeCtx({ decision: 'CHALLENGE', reason: 'mid', score: 0.6 }, { 'x-mfa-token': 'bad' }),
    );
    expect((out as { status: number; body: { error: string } }).status).toBe(401);
    expect((out as { body: { error: string } }).body.error).toBe('mfa_required');
  });

  it('CHALLENGE: createChallenge rate_limited → 429 mfa_rate_limited', async () => {
    const { stage, mfa } = build();
    mfa.createChallenge.mockResolvedValue({ ok: false, reason: 'rate_limited' });
    const out = await stage.run(makeCtx({ decision: 'CHALLENGE', reason: 'mid', score: 0.6 }));
    expect(out).toEqual({
      kind: 'short-circuit',
      status: 429,
      body: { error: 'mfa_rate_limited', requestId: 'req-1' },
    });
  });

  it('CHALLENGE: createChallenge infra error → 503 mfa_<reason>', async () => {
    const { stage, mfa } = build();
    mfa.createChallenge.mockResolvedValue({ ok: false, reason: 'infra' } as never);
    const out = await stage.run(makeCtx({ decision: 'CHALLENGE', reason: 'mid', score: 0.6 }));
    expect((out as { status: number }).status).toBe(503);
  });
});
