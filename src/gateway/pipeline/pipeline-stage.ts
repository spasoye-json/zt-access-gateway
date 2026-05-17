import type { StageContext } from './stage-context';

/**
 * Phase D — Single pipeline stage contract.
 *
 * Each stage is responsible for ONE step of the zero-trust pipeline. The
 * orchestrator iterates an ordered, DI-injected list and dispatches the
 * returned outcome:
 *  - `continue`      → fall through to the next stage
 *  - `bypass`        → middleware invokes `next()` (Express handler chain)
 *  - `short-circuit` → middleware writes the response and returns
 *  - `proxied`       → middleware writes the response + increments allow counter
 *
 * `id` is the metric label passed to `MetricsService.observeStageDuration` and
 * MUST match `^[a-z_]+$` (lowercase + underscore only) so Prometheus label
 * cardinality stays under control.
 */
export interface PipelineStage {
  readonly id: string;
  run(ctx: StageContext): Promise<StageOutcome>;
}

export type StageOutcome =
  | { kind: 'continue' }
  | { kind: 'bypass' }
  | {
      kind: 'short-circuit';
      status: number;
      body: unknown;
      headers?: Record<string, string>;
      // Optional: when true, the stage logger classifies this as a CHALL (not DENY).
      // Use for outcomes that ask the client to do work and retry (e.g. hashcash).
      challenge?: true;
    }
  | { kind: 'proxied'; status: number; body: unknown };
