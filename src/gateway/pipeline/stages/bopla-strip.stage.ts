import { Injectable } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { BoPlaInterceptor } from '../../../proxy/bopla.interceptor';

/**
 * Phase D Stage 12 — BOPLA response stripping (GTWY-06).
 *
 * Applies field-level policy to the upstream response body based on the
 * caller's roles. Admin-always-allow (Phase 8 D-07) is preserved by the
 * underlying BoPlaInterceptor.
 */
@Injectable()
export class BoplaStripStage implements PipelineStage {
  readonly id = 'bopla_strip';

  constructor(private readonly boPla: BoPlaInterceptor) {}

  async run(ctx: StageContext): Promise<StageOutcome> {
    if (!ctx.claims) throw new Error('BoplaStripStage: ctx.claims missing');
    ctx.strippedBody = this.boPla.strip(
      ctx.upstreamBody,
      ctx.reqPath,
      ctx.claims.roles ?? [],
    );
    return { kind: 'continue' };
  }
}
