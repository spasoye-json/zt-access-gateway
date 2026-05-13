import { Injectable } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { PUBLIC_PATHS } from '../../public-paths';

/**
 * Phase D Stage 1 — PUBLIC bypass (D-03 / GTWY-08).
 *
 * /health and /metrics skip the entire zero-trust pipeline. Emits a `bypass`
 * outcome so the middleware invokes Express `next()` and the controller
 * handles the request.
 */
@Injectable()
export class PublicBypassStage implements PipelineStage {
  readonly id = 'public_bypass';

  run(ctx: StageContext): Promise<StageOutcome> {
    return Promise.resolve(
      PUBLIC_PATHS.has(ctx.reqPath) ? { kind: 'bypass' } : { kind: 'continue' },
    );
  }
}
