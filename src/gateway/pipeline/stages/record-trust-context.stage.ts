import { Injectable } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { TrustScoreService } from '../../../trust-score/trust-score.service';

/**
 * Phase D Stage 13 — Terminal stage; records trust context on upstream <400
 * (D-12 / GTWY-05) and emits the `proxied` outcome consumed by writeOutcome
 * to write the upstream response + increment the allow counter.
 *
 * Trust context is recorded ONLY when upstream succeeded (< 400). This
 * preserves the existing Phase D-12 / GTWY-05 invariant — and the broader
 * Phase D-08 rule that trust signals are only retained on successful ALLOWs
 * (CHALLENGE-bypass safety).
 */
@Injectable()
export class RecordTrustContextStage implements PipelineStage {
  readonly id = 'record_trust_context';

  constructor(private readonly trustScore: TrustScoreService) {}

  async run(ctx: StageContext): Promise<StageOutcome> {
    if (ctx.upstreamStatus === undefined) {
      throw new Error('RecordTrustContextStage: ctx.upstreamStatus missing');
    }
    if (ctx.upstreamStatus < 400) {
      if (!ctx.trustCtx || ctx.trustScore === undefined) {
        throw new Error('RecordTrustContextStage: trust ctx/score missing');
      }
      await this.trustScore.recordTrustContextAfterAllow(
        ctx.trustCtx,
        ctx.trustScore,
      );
    }
    return {
      kind: 'proxied',
      status: ctx.upstreamStatus,
      body: ctx.strippedBody,
    };
  }
}
