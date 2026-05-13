import { Injectable } from '@nestjs/common';
import type { StageContext } from '../stage-context';
import type { StageOutcome } from '../pipeline-stage';

export type StageDetailBuilder = (
  ctx: StageContext,
  outcome: StageOutcome,
) => Record<string, string>;

/**
 * Phase Demo — registry of per-stage detail-column builders.
 *
 * Closed-to-modification surface for the StageLoggerDecorator: adding a new
 * pipeline stage is one register() call, never an edit to the logger.
 */
@Injectable()
export class StageDetailRegistry {
  private readonly builders = new Map<string, StageDetailBuilder>();

  register(stageId: string, builder: StageDetailBuilder): void {
    this.builders.set(stageId, builder);
  }

  buildFor(stageId: string, ctx: StageContext, outcome: StageOutcome): Record<string, string> {
    const builder = this.builders.get(stageId);
    if (!builder) return {};
    return builder(ctx, outcome);
  }
}
