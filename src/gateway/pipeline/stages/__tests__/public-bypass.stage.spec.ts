import { PublicBypassStage } from '../public-bypass.stage';
import type { StageContext } from '../../stage-context';

function ctx(p: string): StageContext {
  return { reqPath: p } as unknown as StageContext;
}

describe('PublicBypassStage', () => {
  const s = new PublicBypassStage();

  it('id is "public_bypass"', () => {
    expect(s.id).toBe('public_bypass');
  });

  it('/health → bypass', async () => {
    expect(await s.run(ctx('/health'))).toEqual({ kind: 'bypass' });
  });

  it('/metrics → bypass', async () => {
    expect(await s.run(ctx('/metrics'))).toEqual({ kind: 'bypass' });
  });

  it('any other path → continue', async () => {
    expect(await s.run(ctx('/users/123'))).toEqual({ kind: 'continue' });
    expect(await s.run(ctx('/'))).toEqual({ kind: 'continue' });
  });
});
