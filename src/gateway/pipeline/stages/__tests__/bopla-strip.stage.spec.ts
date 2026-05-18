import { BoplaStripStage } from '../bopla-strip.stage';
import type { StageContext } from '../../stage-context';
import type { BoPlaInterceptor } from '../../../../proxy/bopla.interceptor';

function build(): { stage: BoplaStripStage; boPla: jest.Mocked<BoPlaInterceptor> } {
  const boPla = { strip: jest.fn() } as unknown as jest.Mocked<BoPlaInterceptor>;
  return { stage: new BoplaStripStage(boPla), boPla };
}

function makeCtx(opts: {
  upstreamBody: unknown;
  roles?: string[];
  reqPath?: string;
}): StageContext {
  return {
    req: { headers: {} },
    claims: { userId: 'u1', roles: opts.roles ?? ['user'], jti: 'j', exp: 9, deviceId: 'd1' },
    upstreamBody: opts.upstreamBody,
    reqPath: opts.reqPath ?? '/users/1',
    requestId: 'req-1',
  } as unknown as StageContext;
}

describe('BoplaStripStage', () => {
  it('id is "bopla_strip"', () => {
    expect(build().stage.id).toBe('bopla_strip');
  });

  it('passes upstreamBody, reqPath, claims.roles to BoPlaInterceptor and stashes stripped body', async () => {
    const { stage, boPla } = build();
    boPla.strip.mockReturnValue({ stripped: true });
    const ctx = makeCtx({ upstreamBody: { full: 'body' }, roles: ['user'] });
    const out = await stage.run(ctx);
    expect(out).toEqual({ kind: 'continue' });
    expect(boPla.strip).toHaveBeenCalledWith({ full: 'body' }, '/users/1', ['user']);
    expect(ctx.strippedBody).toEqual({ stripped: true });
  });

  it('claims.roles undefined → []', async () => {
    const { stage, boPla } = build();
    boPla.strip.mockReturnValue('x');
    const ctx = {
      req: { headers: {} },
      claims: { userId: 'u1', roles: undefined, jti: 'j', exp: 9, deviceId: 'd1' },
      upstreamBody: {},
      reqPath: '/x',
      requestId: 'req-1',
    } as unknown as StageContext;
    await stage.run(ctx);
    expect(boPla.strip).toHaveBeenCalledWith({}, '/x', []);
  });

  it('records removed top-level fields when strip drops keys (BOPLA demo log)', async () => {
    const { stage, boPla } = build();
    boPla.strip.mockReturnValue({ id: 'u-1', name: 'Alice', email: 'a@x' });
    const ctx = makeCtx({
      upstreamBody: {
        id: 'u-1',
        name: 'Alice',
        email: 'a@x',
        ssn: '999-99-9999',
        internalRiskScore: 0.42,
      },
      roles: ['user'],
    });
    await stage.run(ctx);
    expect(ctx.boplaRemoved).toEqual(['ssn', 'internalRiskScore']);
  });

  it('omits boplaRemoved when nothing was stripped (admin pass-through)', async () => {
    const { stage, boPla } = build();
    const body = { id: 'u-1', name: 'Alice', email: 'a@x', ssn: '9' };
    boPla.strip.mockReturnValue(body);
    const ctx = makeCtx({ upstreamBody: body, roles: ['admin'] });
    await stage.run(ctx);
    expect(ctx.boplaRemoved).toBeUndefined();
  });

  it('omits boplaRemoved when upstream body is not a plain object', async () => {
    const { stage, boPla } = build();
    boPla.strip.mockReturnValue('text');
    const ctx = makeCtx({ upstreamBody: 'text', roles: ['user'] });
    await stage.run(ctx);
    expect(ctx.boplaRemoved).toBeUndefined();
  });
});
