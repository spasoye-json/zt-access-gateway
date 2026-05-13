import { Inject, Injectable } from '@nestjs/common';
import { PIPELINE_STAGES } from './stage-tokens';
import type { PipelineStage, StageOutcome } from './pipeline-stage';
import type { StageContext } from './stage-context';
import { MetricsService } from '../../metrics/metrics.service';

/**
 * Phase D — Iterates the registered PipelineStage list in order.
 *
 * Single timing rule (Pitfall 7 of the master plan): convert ms→s explicitly
 * at the one callsite. Stage labels (`stage.id`) flow directly into
 * `observeStageDuration` — Task 15 widened that signature to `string` and
 * added a regex guard.
 *
 * Returns immediately on the first non-`continue` outcome. If every stage
 * returns `continue` (e.g. no stages registered or all leaves match nothing)
 * the orchestrator emits `{kind:'continue'}` and the middleware's
 * `writeOutcome` treats that as a programmer error (terminal stages MUST end
 * with `proxied` or `short-circuit`).
 */
@Injectable()
export class PipelineOrchestrator {
  constructor(
    @Inject(PIPELINE_STAGES) private readonly stages: readonly PipelineStage[],
    private readonly metrics: MetricsService,
  ) {}

  async run(ctx: StageContext): Promise<StageOutcome> {
    for (const stage of this.stages) {
      const t0 = Date.now();
      const outcome = await stage.run(ctx);
      this.metrics.observeStageDuration(stage.id, (Date.now() - t0) / 1000);
      if (outcome.kind !== 'continue') return outcome;
    }
    return { kind: 'continue' };
  }
}
