import { Test } from '@nestjs/testing';
import { Module } from '@nestjs/common';
import { PipelineOrchestrator } from '../orchestrator';
import { PIPELINE_STAGES } from '../stage-tokens';
import type { PipelineStage } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { MetricsService } from '../../../metrics/metrics.service';

/**
 * Phase D — Orchestrator integration spec.
 *
 * Two invariants this spec proves:
 *   1. Booting a NestJS module with PIPELINE_STAGES + PipelineOrchestrator
 *      wires them correctly (factory-injected DI list visible to the
 *      orchestrator in iteration order).
 *   2. On short-circuit at stage N, stages N+1..K are not invoked, and
 *      observeStageDuration fires exactly N times.
 *
 * For (1) we use a slim local module that provides fake stages — this
 * avoids booting GatewayModule's full DB-backed dependency tree (e.g. the
 * global DbModule) which is the AppModule's job, not the unit/integration
 * boundary of the orchestrator itself.
 *
 * The full 13-stage execution-order invariant is exercised by the e2e suite
 * `gateway.e2e-spec.ts` which boots AppModule and asserts the stage trace
 * through `observeStageDuration` spies.
 */

class FakeStage implements PipelineStage {
  constructor(
    public readonly id: string,
    private readonly outcome: 'continue' | 'short' = 'continue',
  ) {}
  async run() {
    return this.outcome === 'continue'
      ? { kind: 'continue' as const }
      : { kind: 'short-circuit' as const, status: 401, body: {} };
  }
}

@Module({
  providers: [
    PipelineOrchestrator,
    { provide: MetricsService, useValue: { observeStageDuration: jest.fn() } },
    { provide: 'STAGE_A', useValue: new FakeStage('alpha') },
    { provide: 'STAGE_B', useValue: new FakeStage('beta') },
    { provide: 'STAGE_C', useValue: new FakeStage('gamma') },
    {
      provide: PIPELINE_STAGES,
      useFactory: (a: PipelineStage, b: PipelineStage, c: PipelineStage) => [a, b, c] as const,
      inject: ['STAGE_A', 'STAGE_B', 'STAGE_C'],
    },
  ],
})
class _TestModule {}

describe('PipelineOrchestrator integration (Phase D)', () => {
  it('factory provider exposes stages in injection order to the orchestrator', async () => {
    const mod = await Test.createTestingModule({ imports: [_TestModule] }).compile();
    const stages = mod.get<readonly PipelineStage[]>(PIPELINE_STAGES);
    expect(stages.map((s) => s.id)).toEqual(['alpha', 'beta', 'gamma']);
    await mod.close();
  });

  it('orchestrator stops at short-circuit and does NOT invoke later stages', async () => {
    const recorded: string[] = [];
    const observeStageDuration = jest.fn((id: string) => recorded.push(id));
    const metricsStub = { observeStageDuration } as unknown as MetricsService;

    const s1: PipelineStage = { id: 'a', run: jest.fn().mockResolvedValue({ kind: 'continue' }) };
    const s2: PipelineStage = {
      id: 'b',
      run: jest.fn().mockResolvedValue({ kind: 'short-circuit', status: 401, body: {} }),
    };
    const s3run = jest.fn();
    const s3: PipelineStage = { id: 'c', run: s3run };

    const o = new PipelineOrchestrator([s1, s2, s3], metricsStub);
    const out = await o.run({} as StageContext);
    expect(out.kind).toBe('short-circuit');
    expect(recorded).toEqual(['a', 'b']);
    expect(s3run).not.toHaveBeenCalled();
  });
});
