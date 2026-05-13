import { HashcashStage } from '../hashcash.stage';
import type { StageContext } from '../../stage-context';
import type { HashcashService } from '../../../../hashcash/hashcash.service';
import type { HashcashConfig } from '../../../../config/slices';

function build(cfg: Partial<HashcashConfig> = {}): {
  stage: HashcashStage;
  hc: jest.Mocked<HashcashService>;
} {
  const hc = {
    issueChallenge: jest.fn().mockReturnValue({
      nonce: 'NONCE',
      difficulty: 5,
      expiresAt: 1234567890,
    }),
    verifySolution: jest.fn(),
  } as unknown as jest.Mocked<HashcashService>;
  const fullCfg: HashcashConfig = {
    triggerThreshold: 0.5,
    ...cfg,
  } as HashcashConfig;
  return { stage: new HashcashStage(hc, fullCfg), hc };
}

function makeCtx(opts: { trustScore: number; nonce?: string; solution?: string }): StageContext {
  const headers: Record<string, string | undefined> = {};
  if (opts.nonce !== undefined) headers['x-hashcash-nonce'] = opts.nonce;
  if (opts.solution !== undefined) headers['x-hashcash-solution'] = opts.solution;
  return {
    req: { headers },
    claims: { userId: 'u1', roles: ['user'], jti: 'j', exp: 9, deviceId: 'd1' },
    requestId: 'req-1',
    reqPath: '/x',
    trustScore: opts.trustScore,
  } as unknown as StageContext;
}

describe('HashcashStage', () => {
  it('id is "hashcash"', () => {
    expect(build().stage.id).toBe('hashcash');
  });

  it('trustScore <= threshold → continue (no challenge)', async () => {
    const { stage, hc } = build();
    const out = await stage.run(makeCtx({ trustScore: 0.3 }));
    expect(out).toEqual({ kind: 'continue' });
    expect(hc.issueChallenge).not.toHaveBeenCalled();
  });

  it('trustScore > threshold + missing nonce → 429 proof_of_work_required + challenge headers', async () => {
    const { stage } = build();
    const out = await stage.run(makeCtx({ trustScore: 0.9, solution: 'abc' }));
    expect(out).toEqual({
      kind: 'short-circuit',
      status: 429,
      body: {
        error: 'proof_of_work_required',
        nonce: 'NONCE',
        difficulty: 5,
        expiresAt: 1234567890,
        requestId: 'req-1',
      },
      headers: { 'X-Hashcash-Challenge': 'NONCE:5', 'Retry-After': '1' },
    });
  });

  it('missing solution → proof_of_work_required', async () => {
    const { stage } = build();
    const out = await stage.run(makeCtx({ trustScore: 0.9, nonce: 'N' }));
    expect((out as { body: { error: string } }).body.error).toBe('proof_of_work_required');
  });

  it('solution length > 256 → proof_of_work_invalid', async () => {
    const { stage } = build();
    const out = await stage.run(
      makeCtx({ trustScore: 0.9, nonce: 'N', solution: 's'.repeat(257) }),
    );
    expect((out as { body: { error: string } }).body.error).toBe('proof_of_work_invalid');
  });

  it('verifySolution !ok → proof_of_work_invalid', async () => {
    const { stage, hc } = build();
    hc.verifySolution.mockReturnValue({ ok: false, reason: 'invalid_hmac' });
    const out = await stage.run(makeCtx({ trustScore: 0.9, nonce: 'N', solution: 'abc' }));
    expect((out as { body: { error: string } }).body.error).toBe('proof_of_work_invalid');
  });

  it('verifySolution ok → continue', async () => {
    const { stage, hc } = build();
    hc.verifySolution.mockReturnValue({ ok: true, iat: 1700000000 });
    const out = await stage.run(makeCtx({ trustScore: 0.9, nonce: 'N', solution: 'abc' }));
    expect(out).toEqual({ kind: 'continue' });
  });

  it('uses default threshold 0.5 when not configured', async () => {
    const { stage } = build({ triggerThreshold: undefined });
    expect(await stage.run(makeCtx({ trustScore: 0.49 }))).toEqual({ kind: 'continue' });
    const out = await stage.run(makeCtx({ trustScore: 0.6 }));
    expect((out as { status: number }).status).toBe(429);
  });
});
