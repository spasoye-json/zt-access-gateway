import { Injectable, Logger } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { StageDetailRegistry } from './stage-detail-registry';
import { formatStageLine, StageStatus } from './demo-console-formatter';

const SHORT_REQ_ID_LEN = 8;

function shortRequestId(reqId: string | undefined): string {
  if (!reqId) return '????????';
  // UUIDs contain dashes — drop them so the visible id is 8 hex chars.
  const flat = reqId.replace(/-/g, '');
  return flat.slice(0, SHORT_REQ_ID_LEN).padEnd(SHORT_REQ_ID_LEN, '?');
}

function classify(stageId: string, ctx: StageContext, outcome: StageOutcome): StageStatus {
  if (outcome.kind === 'continue' || outcome.kind === 'proxied') {
    // Slice E (#6): mfa_promotion returning `continue` when the policy stage
    // had decided CHALLENGE means a valid x-mfa-token lifted the gate. Render
    // PROMO instead of PASS so the audience sees the lift visually.
    if (stageId === 'mfa_promotion' && ctx.policyDecision?.decision === 'CHALLENGE') {
      return 'promo';
    }
    return 'pass';
  }
  if (outcome.kind === 'bypass') return 'skip';
  if (outcome.kind === 'short-circuit') {
    if (outcome.challenge === true) return 'chall';
    if (outcome.status === 403) return 'chall';
  }
  return 'deny';
}

/**
 * Phase Demo — wraps a PipelineStage with one-line stdout narration.
 *
 * Each `run()` records the start time, awaits the inner stage, classifies
 * the outcome (pass/deny/chall/skip), measures duration, looks up the
 * per-stage detail builder from {@link StageDetailRegistry}, and emits one
 * formatted line via the Nest Logger. Thrown errors are reported as DENY
 * and re-thrown so the orchestrator's terminal-error path is unchanged.
 */
@Injectable()
export class StageLoggerDecorator {
  private readonly logger = new Logger('Stage');

  constructor(private readonly details: StageDetailRegistry) {}

  wrap(stage: PipelineStage): PipelineStage {
    const details = this.details;
    const logger = this.logger;
    return {
      id: stage.id,
      async run(ctx: StageContext): Promise<StageOutcome> {
        const t0 = Date.now();
        try {
          const outcome = await stage.run(ctx);
          const ms = Date.now() - t0;
          const detail = details.buildFor(stage.id, ctx, outcome);
          logger.log(
            formatStageLine(
              shortRequestId(ctx.requestId),
              stage.id,
              classify(stage.id, ctx, outcome),
              ms,
              detail,
            ),
          );
          return outcome;
        } catch (e) {
          const ms = Date.now() - t0;
          logger.log(
            formatStageLine(shortRequestId(ctx.requestId), stage.id, 'deny', ms, {
              error: (e as Error).message || 'thrown',
            }),
          );
          throw e;
        }
      },
    };
  }
}
