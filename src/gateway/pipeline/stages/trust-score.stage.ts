import { Injectable } from '@nestjs/common';
import type { Request } from 'express';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { TrustScoreService } from '../../../trust-score/trust-score.service';
import { DemoModeService } from '../../../shared/demo-mode/demo-mode.service';
import { extractIp } from '../../../shared/request-context.util';
import type { TrustContext } from '../../../trust-score/trust-context';

const DEMO_TRUST_SCORE_HEADER = 'x-demo-trust-score';

function parseDemoOverride(raw: string | string[] | undefined): number | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (trimmed === '') return null;
  const n = Number(trimmed);
  if (!Number.isFinite(n) || n < 0 || n > 1) return null;
  return n;
}

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

  constructor(
    private readonly trustScore: TrustScoreService,
    private readonly demoMode: DemoModeService,
  ) {}

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

    // Demo override (PRD #1 user stories 9–11). Honoured only when DEMO_MODE
    // is active AND the header parses to a finite number in [0, 1]. Anything
    // else falls through to the real providers — never crash, never wrongly
    // allow a typo'd value.
    const override = this.demoMode.isActive()
      ? parseDemoOverride(ctx.req.headers[DEMO_TRUST_SCORE_HEADER])
      : null;

    const value = override !== null ? override : await this.trustScore.evaluateScore(trustCtx);

    ctx.trustScore = value;
    ctx.trustCtx = trustCtx;
    if (override !== null) ctx.trustOverride = 'demo';
    (ctx.req as Request & { trustScore?: number }).trustScore = value;
    return { kind: 'continue' };
  }
}
