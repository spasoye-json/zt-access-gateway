import type { Response, NextFunction } from 'express';
import type { StageOutcome } from './pipeline-stage';
import type { MetricsService } from '../../metrics/metrics.service';

/**
 * Phase D — Single response-writing seam.
 *
 * Stages return a `StageOutcome`; the middleware passes it here so all
 * `res.*` mutations + the `incrementRequest('allow')` increment live in
 * one auditable place. A returned `continue` outcome from the orchestrator
 * means no terminal stage fired — that is a programmer error (the pipeline
 * MUST end with `proxied` or `short-circuit`).
 */
export function writeOutcome(
  res: Response,
  next: NextFunction,
  outcome: StageOutcome,
  metrics: MetricsService,
): void {
  switch (outcome.kind) {
    case 'bypass':
      next();
      return;
    case 'short-circuit': {
      if (outcome.headers) {
        for (const [k, v] of Object.entries(outcome.headers)) {
          res.set(k, v);
        }
      }
      res.status(outcome.status).json(outcome.body);
      return;
    }
    case 'proxied':
      metrics.incrementRequest('allow');
      res.status(outcome.status).json(outcome.body);
      return;
    case 'continue':
      throw new Error(
        'orchestrator returned continue; pipeline did not terminate',
      );
  }
}
