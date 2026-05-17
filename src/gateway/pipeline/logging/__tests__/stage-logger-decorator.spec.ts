import chalk from 'chalk';
import { Logger } from '@nestjs/common';
import { StageLoggerDecorator } from '../stage-logger-decorator';
import { StageDetailRegistry } from '../stage-detail-registry';
import type { PipelineStage, StageOutcome } from '../../pipeline-stage';
import type { StageContext } from '../../stage-context';

beforeAll(() => {
  chalk.level = 1;
});

function makeStage(id: string, outcome: StageOutcome | Error): PipelineStage {
  return {
    id,
    run: async () => {
      if (outcome instanceof Error) throw outcome;
      return outcome;
    },
  };
}

function makeCtx(): StageContext {
  return { requestId: 'abcdef01', startedAt: Date.now() } as StageContext;
}

describe('StageLoggerDecorator', () => {
  let logs: string[];
  let spy: jest.SpyInstance;

  beforeEach(() => {
    logs = [];
    spy = jest.spyOn(Logger.prototype, 'log').mockImplementation((msg) => {
      logs.push(String(msg));
    });
  });

  afterEach(() => {
    spy.mockRestore();
  });

  it('preserves the underlying stage id on the wrapper', () => {
    const inner = makeStage('auth', { kind: 'continue' });
    const wrapped = new StageLoggerDecorator(new StageDetailRegistry()).wrap(inner);
    expect(wrapped.id).toBe('auth');
  });

  it('emits one PASS line when the inner stage returns continue', async () => {
    const inner = makeStage('auth', { kind: 'continue' });
    const wrapped = new StageLoggerDecorator(new StageDetailRegistry()).wrap(inner);

    const outcome = await wrapped.run(makeCtx());

    expect(outcome).toEqual({ kind: 'continue' });
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain('abcdef01');
    expect(logs[0]).toContain('auth');
    expect(logs[0]).toContain('PASS');
  });

  it('emits one DENY line when the inner stage short-circuits', async () => {
    const inner = makeStage('auth', { kind: 'short-circuit', status: 401, body: {} });
    const wrapped = new StageLoggerDecorator(new StageDetailRegistry()).wrap(inner);

    const outcome = await wrapped.run(makeCtx());

    expect(outcome.kind).toBe('short-circuit');
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain('DENY');
  });

  it('emits one CHALL line when the inner stage short-circuits with 403', async () => {
    const inner = makeStage('mfa', { kind: 'short-circuit', status: 403, body: {} });
    const wrapped = new StageLoggerDecorator(new StageDetailRegistry()).wrap(inner);

    await wrapped.run(makeCtx());

    expect(logs[0]).toContain('CHALL');
    expect(logs[0]).toContain('mfa');
  });

  it('emits one CHALL line when the inner stage short-circuits with challenge=true', async () => {
    const inner = makeStage('hashcash', {
      kind: 'short-circuit',
      status: 429,
      body: {},
      challenge: true,
    });
    const wrapped = new StageLoggerDecorator(new StageDetailRegistry()).wrap(inner);

    await wrapped.run(makeCtx());

    expect(logs[0]).toContain('CHALL');
    expect(logs[0]).toContain('hashcash');
  });

  it('emits one DENY line and re-throws when the inner stage throws', async () => {
    const inner = makeStage('proxy', new Error('boom'));
    const wrapped = new StageLoggerDecorator(new StageDetailRegistry()).wrap(inner);

    await expect(wrapped.run(makeCtx())).rejects.toThrow('boom');
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain('DENY');
    expect(logs[0]).toContain('proxy');
  });

  it('emits SKIP when the stage returns bypass', async () => {
    const inner = makeStage('public-bypass', { kind: 'bypass' });
    const wrapped = new StageLoggerDecorator(new StageDetailRegistry()).wrap(inner);

    await wrapped.run(makeCtx());

    expect(logs[0]).toContain('SKIP');
  });

  it('emits PROMO for mfa_promotion when CHALLENGE is lifted by a valid x-mfa-token', async () => {
    const inner = makeStage('mfa_promotion', { kind: 'continue' });
    const wrapped = new StageLoggerDecorator(new StageDetailRegistry()).wrap(inner);
    const ctx = {
      requestId: 'abcdef01',
      startedAt: Date.now(),
      policyDecision: { decision: 'CHALLENGE' },
    } as StageContext;

    await wrapped.run(ctx);

    expect(logs[0]).toContain('PROMO');
    expect(logs[0]).toContain('mfa_promotion');
  });

  it('emits PASS (not PROMO) for mfa_promotion when policy already decided ALLOW', async () => {
    const inner = makeStage('mfa_promotion', { kind: 'continue' });
    const wrapped = new StageLoggerDecorator(new StageDetailRegistry()).wrap(inner);
    const ctx = {
      requestId: 'abcdef01',
      startedAt: Date.now(),
      policyDecision: { decision: 'ALLOW' },
    } as StageContext;

    await wrapped.run(ctx);

    expect(logs[0]).toContain('PASS');
    expect(logs[0]).not.toContain('PROMO');
  });

  it('renders detail kvs from the registered builder', async () => {
    const inner = makeStage('auth', { kind: 'continue' });
    const registry = new StageDetailRegistry();
    registry.register('auth', () => ({ user: 'alice', alg: 'HS256' }));
    const wrapped = new StageLoggerDecorator(registry).wrap(inner);

    await wrapped.run(makeCtx());

    expect(logs[0]).toContain('user=alice');
    expect(logs[0]).toContain('alg=HS256');
  });
});
