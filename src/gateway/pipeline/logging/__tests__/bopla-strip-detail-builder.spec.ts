import { StageDetailRegistry } from '../stage-detail-registry';
import { registerDefaultDetailBuilders } from '../default-detail-builders';
import type { StageContext } from '../../stage-context';

function ctxWith(partial: Partial<StageContext>): StageContext {
  return partial as StageContext;
}

describe('bopla_strip detail builder', () => {
  it('renders removed=[…] when boplaRemoved is populated', () => {
    const r = new StageDetailRegistry();
    registerDefaultDetailBuilders(r);
    const out = r.buildFor(
      'bopla_strip',
      ctxWith({ strippedBody: {}, boplaRemoved: ['ssn', 'internalRiskScore'] }),
      { kind: 'continue' },
    );
    expect(out).toEqual({ removed: '[ssn,internalRiskScore]' });
  });

  it('falls back to stripped=yes when strip ran but removed nothing', () => {
    const r = new StageDetailRegistry();
    registerDefaultDetailBuilders(r);
    const out = r.buildFor('bopla_strip', ctxWith({ strippedBody: { a: 1 } }), {
      kind: 'continue',
    });
    expect(out).toEqual({ stripped: 'yes' });
  });

  it('emits nothing when bopla_strip did not run', () => {
    const r = new StageDetailRegistry();
    registerDefaultDetailBuilders(r);
    expect(r.buildFor('bopla_strip', ctxWith({}), { kind: 'continue' })).toEqual({});
  });
});
