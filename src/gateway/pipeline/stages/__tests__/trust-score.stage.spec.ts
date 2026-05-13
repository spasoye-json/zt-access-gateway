import { TrustScoreStage } from '../trust-score.stage';
import type { StageContext } from '../../stage-context';
import type { TrustScoreService } from '../../../../trust-score/trust-score.service';

function build(): { stage: TrustScoreStage; ts: jest.Mocked<TrustScoreService> } {
  const ts = { evaluateScore: jest.fn() } as unknown as jest.Mocked<TrustScoreService>;
  return { stage: new TrustScoreStage(ts), ts };
}

function makeCtx(opts: { deviceId?: string; ja4h?: string } = {}): StageContext {
  return {
    req: { headers: {}, ip: '1.2.3.4', socket: { remoteAddress: '1.2.3.4' } },
    claims: {
      userId: 'u1',
      roles: ['user'],
      jti: 'j',
      exp: 9,
      deviceId: opts.deviceId ?? 'd1',
    },
    requestId: 'req-1',
    reqPath: '/users/1',
    ja4h: opts.ja4h,
  } as unknown as StageContext;
}

describe('TrustScoreStage', () => {
  it('id is "trust_score"', () => {
    expect(build().stage.id).toBe('trust_score');
  });

  it('evaluates score and stashes on ctx + req', async () => {
    const { stage, ts } = build();
    ts.evaluateScore.mockResolvedValue(0.42);
    const ctx = makeCtx({ ja4h: 'fp' });
    const out = await stage.run(ctx);
    expect(out).toEqual({ kind: 'continue' });
    expect(ctx.trustScore).toBe(0.42);
    expect(ctx.trustCtx).toEqual({ userId: 'u1', deviceId: 'd1', ip: '1.2.3.4', ja4h: 'fp' });
    expect((ctx.req as unknown as { trustScore: number }).trustScore).toBe(0.42);
    expect(ts.evaluateScore).toHaveBeenCalledTimes(1);
  });

  it('deviceId undefined → empty string in trustCtx', async () => {
    const { stage, ts } = build();
    ts.evaluateScore.mockResolvedValue(0.1);
    const ctx = makeCtx({ deviceId: '' });
    await stage.run(ctx);
    expect(ctx.trustCtx?.deviceId).toBe('');
  });

  it('ja4h undefined → empty string in trustCtx', async () => {
    const { stage, ts } = build();
    ts.evaluateScore.mockResolvedValue(0.1);
    const ctx = makeCtx();
    await stage.run(ctx);
    expect(ctx.trustCtx?.ja4h).toBe('');
  });
});
