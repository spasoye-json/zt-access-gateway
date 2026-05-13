import { ProxyStage } from '../proxy.stage';
import type { StageContext } from '../../stage-context';
import type { ProxyService } from '../../../../proxy/proxy.service';

function build(): { stage: ProxyStage; proxy: jest.Mocked<ProxyService> } {
  const proxy = { forward: jest.fn() } as unknown as jest.Mocked<ProxyService>;
  return { stage: new ProxyStage(proxy), proxy };
}

function makeCtx(): StageContext {
  return {
    req: { headers: {} },
    claims: { userId: 'u1', roles: ['user'], jti: 'j', exp: 9, deviceId: 'd1' },
    trustScore: 0.3,
    requestId: 'req-1',
    reqPath: '/x',
  } as unknown as StageContext;
}

describe('ProxyStage', () => {
  it('id is "proxy"', () => {
    expect(build().stage.id).toBe('proxy');
  });

  it('forwards request and stashes upstream status/body + continue', async () => {
    const { stage, proxy } = build();
    proxy.forward.mockResolvedValue({ status: 201, data: { id: 'x' } } as never);
    const ctx = makeCtx();
    const out = await stage.run(ctx);
    expect(out).toEqual({ kind: 'continue' });
    expect(ctx.upstreamStatus).toBe(201);
    expect(ctx.upstreamBody).toEqual({ id: 'x' });
    expect(proxy.forward).toHaveBeenCalledWith(ctx.req, ctx.claims, 0.3);
  });
});
