import { Injectable, Logger, NestMiddleware } from '@nestjs/common';
import type { Request, Response, NextFunction } from 'express';
import { TypedEvents } from '../shared/typed-events';
import { MetricsService } from '../metrics/metrics.service';
import { PipelineOrchestrator } from './pipeline/orchestrator';
import { buildStageContext } from './pipeline/build-stage-context';
import { writeOutcome } from './pipeline/write-outcome';
import { handleTerminalError } from './pipeline/handle-terminal-error';

/**
 * Phase D — GatewayMiddleware reduced to a thin orchestration shell.
 *
 * Responsibilities:
 *   1. CORS preflight short-circuit (req.method === 'OPTIONS' → next())
 *   2. Build StageContext (requestId, ja4h, reqPath, startedAt)
 *   3. Delegate to PipelineOrchestrator (iterates the PIPELINE_STAGES list)
 *   4. Dispatch the returned outcome through writeOutcome
 *   5. Catch terminal exceptions (AuditExhausted / ServiceUnavailable /
 *      Unauthorized) via handleTerminalError; re-throw everything else
 *
 * All pipeline behaviour lives in the 13 stage adapters under
 * src/gateway/pipeline/stages. Adding a new stage = one new file + one entry
 * in the PIPELINE_STAGES factory provider in gateway.module.ts.
 */
@Injectable()
export class GatewayMiddleware implements NestMiddleware {
  private readonly logger = new Logger(GatewayMiddleware.name);

  constructor(
    private readonly orchestrator: PipelineOrchestrator,
    private readonly events: TypedEvents,
    private readonly metrics: MetricsService,
  ) {}

  async use(req: Request, res: Response, next: NextFunction): Promise<void> {
    if (req.method === 'OPTIONS') return next();
    const ctx = buildStageContext(req, res, next);
    try {
      const outcome = await this.orchestrator.run(ctx);
      writeOutcome(res, next, outcome, this.metrics);
    } catch (e) {
      handleTerminalError(res, e, ctx, this.events, this.metrics, this.logger);
    }
  }
}
