import chalk from 'chalk';
import { Logger } from '@nestjs/common';
import { wrapStages, SILENT_STAGE_IDS } from '../wrap-stages';
import { StageDetailRegistry } from '../stage-detail-registry';
import { StageLoggerDecorator } from '../stage-logger-decorator';
import type { PipelineStage, StageOutcome } from '../../pipeline-stage';
import type { StageContext } from '../../stage-context';

beforeAll(() => {
  chalk.level = 1;
});

function fakeStage(id: string): PipelineStage {
  return {
    id,
    run: async (): Promise<StageOutcome> => ({ kind: 'continue' }),
  };
}

describe('wrapStages', () => {
  let logs: string[];
  let spy: jest.SpyInstance;
  beforeEach(() => {
    logs = [];
    spy = jest.spyOn(Logger.prototype, 'log').mockImplementation((m) => {
      logs.push(String(m));
    });
  });
  afterEach(() => spy.mockRestore());

  it('preserves the input order and length', () => {
    const decorator = new StageLoggerDecorator(new StageDetailRegistry());
    const stages = [fakeStage('a'), fakeStage('b'), fakeStage('c')];
    const wrapped = wrapStages(stages, decorator);
    expect(wrapped.map((s) => s.id)).toEqual(['a', 'b', 'c']);
  });

  it('emits log lines for non-silent stages', async () => {
    const decorator = new StageLoggerDecorator(new StageDetailRegistry());
    const wrapped = wrapStages([fakeStage('auth')], decorator);
    await wrapped[0].run({ requestId: 'r' } as StageContext);
    expect(logs).toHaveLength(1);
  });

  it('does NOT emit log lines for silent stage ids (audit_allow, record_trust_context)', async () => {
    const decorator = new StageLoggerDecorator(new StageDetailRegistry());
    const wrapped = wrapStages(
      [fakeStage('audit_allow'), fakeStage('record_trust_context')],
      decorator,
    );
    await wrapped[0].run({ requestId: 'r' } as StageContext);
    await wrapped[1].run({ requestId: 'r' } as StageContext);
    expect(logs).toEqual([]);
  });

  it('exports the canonical silent set', () => {
    expect(SILENT_STAGE_IDS).toEqual(new Set(['audit_allow', 'record_trust_context']));
  });
});
