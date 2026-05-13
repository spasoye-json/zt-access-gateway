import { RecordTrustContextStage } from '../record-trust-context.stage';
import type { StageContext } from '../../stage-context';
import type { TrustScoreService } from '../../../../trust-score/trust-score.service';

function build(): {
  stage: RecordTrustContextStage;
  ts: jest.Mocked<TrustScoreService>;
} {
  const ts = {
    recordTrustContextAfterAllow: jest.fn().mockResolvedValue(undefined),
  } as unknown as jest.Mocked<TrustScoreService>;
  return { stage: new RecordTrustContextStage(ts), ts };
}

function makeCtx(opts: { status: number }): StageContext {
  return {
    req: { headers: {} },
    requestId: 'r',
    reqPath: '/x',
    trustCtx: { userId: 'u1', deviceId: 'd1', ip: '1.1.1.1', ja4h: 'fp' },
    trustScore: 0.3,
    upstreamStatus: opts.status,
    strippedBody: { id: 'x' },
  } as unknown as StageContext;
}

describe('RecordTrustContextStage', () => {
  it('id is "record_trust_context"', () => {
    expect(build().stage.id).toBe('record_trust_context');
  });

  it('upstream 200 → record called + proxied outcome', async () => {
    const { stage, ts } = build();
    const out = await stage.run(makeCtx({ status: 200 }));
    expect(ts.recordTrustContextAfterAllow).toHaveBeenCalledTimes(1);
    expect(out).toEqual({ kind: 'proxied', status: 200, body: { id: 'x' } });
  });

  it('upstream 404 → record NOT called + proxied outcome with 404', async () => {
    const { stage, ts } = build();
    const out = await stage.run(makeCtx({ status: 404 }));
    expect(ts.recordTrustContextAfterAllow).not.toHaveBeenCalled();
    expect(out).toEqual({ kind: 'proxied', status: 404, body: { id: 'x' } });
  });

  it('upstream 500 → record NOT called', async () => {
    const { stage, ts } = build();
    await stage.run(makeCtx({ status: 500 }));
    expect(ts.recordTrustContextAfterAllow).not.toHaveBeenCalled();
  });

  it('upstream 399 → record called (< 400 boundary)', async () => {
    const { stage, ts } = build();
    await stage.run(makeCtx({ status: 399 }));
    expect(ts.recordTrustContextAfterAllow).toHaveBeenCalledTimes(1);
  });
});
