import { PolicyStage } from '../policy.stage';
import type { StageContext } from '../../stage-context';
import type { PolicyEvaluatorService } from '../../../../policy/policy-evaluator.service';

function build(): { stage: PolicyStage; policy: jest.Mocked<PolicyEvaluatorService> } {
  const policy = { evaluate: jest.fn() } as unknown as jest.Mocked<PolicyEvaluatorService>;
  return { stage: new PolicyStage(policy), policy };
}

function makeCtx(): StageContext {
  return {
    req: { headers: {} },
    requestId: 'req-1',
    reqPath: '/x',
  } as unknown as StageContext;
}

describe('PolicyStage', () => {
  it('id is "policy"', () => {
    expect(build().stage.id).toBe('policy');
  });

  it('ALLOW → ctx.policyDecision set + continue', async () => {
    const { stage, policy } = build();
    const dec = { decision: 'ALLOW' as const, reason: 'ok', score: 0.2, matchedSubject: 'user:u1' };
    policy.evaluate.mockResolvedValue(dec);
    const ctx = makeCtx();
    const out = await stage.run(ctx);
    expect(out).toEqual({ kind: 'continue' });
    expect(ctx.policyDecision).toBe(dec);
  });

  it('CHALLENGE → stashes + continue', async () => {
    const { stage, policy } = build();
    const dec = { decision: 'CHALLENGE' as const, reason: 'mid-risk', score: 0.6 };
    policy.evaluate.mockResolvedValue(dec);
    const ctx = makeCtx();
    await stage.run(ctx);
    expect(ctx.policyDecision).toBe(dec);
  });

  it('DENY → stashes + continue (no short-circuit here — downstream handles)', async () => {
    const { stage, policy } = build();
    const dec = { decision: 'DENY' as const, reason: 'blacklist', score: 0.95 };
    policy.evaluate.mockResolvedValue(dec);
    const ctx = makeCtx();
    const out = await stage.run(ctx);
    expect(out).toEqual({ kind: 'continue' });
    expect(ctx.policyDecision).toBe(dec);
  });
});
