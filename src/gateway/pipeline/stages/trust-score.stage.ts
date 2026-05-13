import { Injectable } from '@nestjs/common';
import type { Request } from 'express';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { TrustScoreService } from '../../../trust-score/trust-score.service';
import { extractIp } from '../../../shared/request-context.util';
import type { TrustContext } from '../../../trust-score/trust-context';

/**
 * Phase D Stage 6 — Trust score evaluation (D-13).
 *
 * Builds the TrustContext, calls TrustScoreService.evaluateScore once per
 * request, and stashes the result on both `ctx.trustScore` and the legacy
 * `req.trustScore` (consumed by downstream guards/controllers).
 *
 * Always returns `continue` — risk is interpreted by later stages (hashcash,
 * policy).
 */
@Injectable()
export class TrustScoreStage implements PipelineStage {
  readonly id = 'trust_score';

  constructor(private readonly trustScore: TrustScoreService) {}

  async run(ctx: StageContext): Promise<StageOutcome> {
    if (!ctx.claims) {
      throw new Error('TrustScoreStage: ctx.claims missing');
    }
    const trustCtx: TrustContext = {
      userId: ctx.claims.userId,
      deviceId: ctx.claims.deviceId || '',
      ip: extractIp(ctx.req),
      ja4h: ctx.ja4h ?? '',
    };
    const value = await this.trustScore.evaluateScore(trustCtx);
    ctx.trustScore = value;
    ctx.trustCtx = trustCtx;
    (ctx.req as Request & { trustScore?: number }).trustScore = value;
    return { kind: 'continue' };
  }
}
