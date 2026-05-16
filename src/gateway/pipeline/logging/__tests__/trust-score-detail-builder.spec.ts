import { StageDetailRegistry } from '../stage-detail-registry';
import { registerDefaultDetailBuilders } from '../default-detail-builders';
import type { StageContext } from '../../stage-context';

function ctxWith(partial: Partial<StageContext>): StageContext {
  return partial as StageContext;
}

describe('trust_score detail builder', () => {
  it('renders score only when no override is present', () => {
    const r = new StageDetailRegistry();
    registerDefaultDetailBuilders(r);
    const out = r.buildFor('trust_score', ctxWith({ trustScore: 0.65 }), { kind: 'continue' });
    expect(out).toEqual({ score: '0.65' });
  });

  it('appends override=demo when the override was honoured', () => {
    const r = new StageDetailRegistry();
    registerDefaultDetailBuilders(r);
    const out = r.buildFor('trust_score', ctxWith({ trustScore: 0.0, trustOverride: 'demo' }), {
      kind: 'continue',
    });
    expect(out).toEqual({ score: '0.00', override: 'demo' });
  });
});
