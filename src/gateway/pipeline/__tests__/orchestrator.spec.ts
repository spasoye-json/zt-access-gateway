import { PipelineOrchestrator } from '../orchestrator';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import type { MetricsService } from '../../../metrics/metrics.service';

function makeStage(id: string, outcome: StageOutcome): PipelineStage & { runMock: jest.Mock } {
  const runMock = jest.fn().mockResolvedValue(outcome);
  return { id, run: runMock as PipelineStage['run'], runMock };
}

function makeMetricsMock(): jest.Mocked<Pick<MetricsService, 'observeStageDuration'>> {
  return { observeStageDuration: jest.fn() } as unknown as jest.Mocked<
    Pick<MetricsService, 'observeStageDuration'>
  >;
}

const emptyCtx = { startedAt: Date.now() } as unknown as StageContext;

describe('PipelineOrchestrator', () => {
  it('returns {continue} when zero stages registered', async () => {
    const metrics = makeMetricsMock();
    const o = new PipelineOrchestrator([], metrics as unknown as MetricsService);
    expect(await o.run(emptyCtx)).toEqual({ kind: 'continue' });
    expect(metrics.observeStageDuration).not.toHaveBeenCalled();
  });

  it('iterates all stages when each returns continue and ends with the terminal outcome', async () => {
    const s1 = makeStage('s1', { kind: 'continue' });
    const s2 = makeStage('s2', { kind: 'continue' });
    const terminal = makeStage('terminal', {
      kind: 'short-circuit',
      status: 418,
      body: { foo: 'bar' },
    });
    const metrics = makeMetricsMock();
    const o = new PipelineOrchestrator(
      [s1, s2, terminal],
      metrics as unknown as MetricsService,
    );
    const out = await o.run(emptyCtx);
    expect(out).toEqual({ kind: 'short-circuit', status: 418, body: { foo: 'bar' } });
    expect(s1.runMock).toHaveBeenCalledTimes(1);
    expect(s2.runMock).toHaveBeenCalledTimes(1);
    expect(terminal.runMock).toHaveBeenCalledTimes(1);
    expect(metrics.observeStageDuration).toHaveBeenCalledTimes(3);
    expect(metrics.observeStageDuration.mock.calls.map((c) => c[0])).toEqual([
      's1',
      's2',
      'terminal',
    ]);
  });

  it('stops at the first short-circuit and does NOT invoke later stages', async () => {
    const s1 = makeStage('s1', { kind: 'continue' });
    const s2 = makeStage('s2', {
      kind: 'short-circuit',
      status: 401,
      body: { error: 'nope' },
    });
    const s3 = makeStage('s3', { kind: 'continue' });
    const metrics = makeMetricsMock();
    const o = new PipelineOrchestrator(
      [s1, s2, s3],
      metrics as unknown as MetricsService,
    );
    const out = await o.run(emptyCtx);
    expect(out.kind).toBe('short-circuit');
    expect(s1.runMock).toHaveBeenCalledTimes(1);
    expect(s2.runMock).toHaveBeenCalledTimes(1);
    expect(s3.runMock).not.toHaveBeenCalled();
    expect(metrics.observeStageDuration).toHaveBeenCalledTimes(2);
    expect(metrics.observeStageDuration.mock.calls.map((c) => c[0])).toEqual(['s1', 's2']);
  });

  it('passes a seconds-scale duration (not milliseconds)', async () => {
    const s1 = makeStage('s1', { kind: 'continue' });
    const metrics = makeMetricsMock();
    const o = new PipelineOrchestrator([s1], metrics as unknown as MetricsService);
    await o.run(emptyCtx);
    const seconds = metrics.observeStageDuration.mock.calls[0][1];
    // anything that completes in test time should be sub-second
    expect(seconds).toBeLessThan(1);
    expect(seconds).toBeGreaterThanOrEqual(0);
  });

  it('stops at bypass outcome', async () => {
    const s1 = makeStage('s1', { kind: 'bypass' });
    const s2 = makeStage('s2', { kind: 'continue' });
    const metrics = makeMetricsMock();
    const o = new PipelineOrchestrator([s1, s2], metrics as unknown as MetricsService);
    const out = await o.run(emptyCtx);
    expect(out).toEqual({ kind: 'bypass' });
    expect(s2.runMock).not.toHaveBeenCalled();
  });
});
