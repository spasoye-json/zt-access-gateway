import { TrustScoreStage } from '../trust-score.stage';
import type { StageContext } from '../../stage-context';
import type { TrustScoreService } from '../../../../trust-score/trust-score.service';
import type { DemoModeService } from '../../../../shared/demo-mode/demo-mode.service';

function build(demoActive = false): {
  stage: TrustScoreStage;
  ts: jest.Mocked<TrustScoreService>;
  demo: jest.Mocked<DemoModeService>;
} {
  const ts = { evaluateScore: jest.fn() } as unknown as jest.Mocked<TrustScoreService>;
  const demo = {
    isActive: jest.fn().mockReturnValue(demoActive),
  } as unknown as jest.Mocked<DemoModeService>;
  return { stage: new TrustScoreStage(ts, demo), ts, demo };
}

function makeCtx(
  opts: { deviceId?: string; ja4h?: string; headers?: Record<string, string> } = {},
): StageContext {
  return {
    req: {
      headers: opts.headers ?? {},
      ip: '1.2.3.4',
      socket: { remoteAddress: '1.2.3.4' },
    },
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

  describe('DEMO_MODE x-demo-trust-score override', () => {
    it('uses the header value as the trust score and bypasses TrustScoreService', async () => {
      const { stage, ts } = build(true);
      const ctx = makeCtx({ headers: { 'x-demo-trust-score': '0.0' } });

      const out = await stage.run(ctx);

      expect(out).toEqual({ kind: 'continue' });
      expect(ctx.trustScore).toBe(0);
      expect(ts.evaluateScore).not.toHaveBeenCalled();
    });

    it('ignores the header when DEMO_MODE is inactive', async () => {
      const { stage, ts } = build(false);
      ts.evaluateScore.mockResolvedValue(0.42);
      const ctx = makeCtx({ headers: { 'x-demo-trust-score': '0.0' } });

      await stage.run(ctx);

      expect(ctx.trustScore).toBe(0.42);
      expect(ts.evaluateScore).toHaveBeenCalledTimes(1);
    });

    it("sets ctx.trustOverride to 'demo' when the override is honoured", async () => {
      const { stage } = build(true);
      const ctx = makeCtx({ headers: { 'x-demo-trust-score': '0.25' } });

      await stage.run(ctx);

      expect(ctx.trustScore).toBe(0.25);
      expect(ctx.trustOverride).toBe('demo');
    });

    it.each(['not-a-number', '-0.01', '1.01', 'NaN', '', '  '])(
      'ignores invalid header value %p and falls through to real providers',
      async (raw) => {
        const { stage, ts } = build(true);
        ts.evaluateScore.mockResolvedValue(0.42);
        const ctx = makeCtx({ headers: { 'x-demo-trust-score': raw } });

        await stage.run(ctx);

        expect(ctx.trustScore).toBe(0.42);
        expect(ts.evaluateScore).toHaveBeenCalledTimes(1);
        expect(ctx.trustOverride).toBeUndefined();
      },
    );
  });
});
