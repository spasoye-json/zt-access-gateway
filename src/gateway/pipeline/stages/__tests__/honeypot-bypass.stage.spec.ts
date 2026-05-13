import { HoneypotBypassStage } from '../honeypot-bypass.stage';
import type { StageContext } from '../../stage-context';
import { HONEYPOT_PATHS } from '../../../../honeypot/honeypot.constants';

function ctx(p: string): StageContext {
  return { reqPath: p } as unknown as StageContext;
}

describe('HoneypotBypassStage', () => {
  const s = new HoneypotBypassStage();

  it('id is "honeypot_bypass"', () => {
    expect(s.id).toBe('honeypot_bypass');
  });

  it('every HONEYPOT_PATHS member → bypass', async () => {
    for (const p of HONEYPOT_PATHS) {
      expect(await s.run(ctx(p))).toEqual({ kind: 'bypass' });
    }
  });

  it('regular path → continue', async () => {
    expect(await s.run(ctx('/users/123'))).toEqual({ kind: 'continue' });
  });
});
