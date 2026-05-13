import { StageDetailRegistry } from '../stage-detail-registry';
import type { StageContext } from '../../stage-context';
import type { StageOutcome } from '../../pipeline-stage';

const ctx = {} as StageContext;
const okOutcome: StageOutcome = { kind: 'continue' };

describe('StageDetailRegistry', () => {
  it('returns an empty object for an unregistered stage id', () => {
    const r = new StageDetailRegistry();
    expect(r.buildFor('auth', ctx, okOutcome)).toEqual({});
  });

  it('returns the registered builder output for a known stage id', () => {
    const r = new StageDetailRegistry();
    r.register('auth', (_c, _o) => ({ user: 'alice', alg: 'HS256' }));
    expect(r.buildFor('auth', ctx, okOutcome)).toEqual({ user: 'alice', alg: 'HS256' });
  });

  it('isolates builders per stage id', () => {
    const r = new StageDetailRegistry();
    r.register('auth', () => ({ user: 'alice' }));
    r.register('policy', () => ({ decision: 'allow' }));
    expect(r.buildFor('auth', ctx, okOutcome)).toEqual({ user: 'alice' });
    expect(r.buildFor('policy', ctx, okOutcome)).toEqual({ decision: 'allow' });
  });

  it('passes the context and outcome to the builder', () => {
    const r = new StageDetailRegistry();
    const seen: { ctx: StageContext; outcome: StageOutcome }[] = [];
    r.register('auth', (c, o) => {
      seen.push({ ctx: c, outcome: o });
      return {};
    });
    const ctx2 = { requestId: 'r1' } as StageContext;
    const outcome2: StageOutcome = { kind: 'short-circuit', status: 401, body: {} };
    r.buildFor('auth', ctx2, outcome2);
    expect(seen).toEqual([{ ctx: ctx2, outcome: outcome2 }]);
  });
});
