import type { PipelineStage } from '../pipeline-stage';
import { StageLoggerDecorator } from './stage-logger-decorator';

/**
 * Stage ids whose execution is fire-and-forget telemetry and MUST NOT show
 * up in the per-request narrative. Keeping these silent prevents the
 * audience from mistaking a write-through for a decision point.
 */
export const SILENT_STAGE_IDS: ReadonlySet<string> = new Set([
  'audit_allow',
  'record_trust_context',
]);

export function wrapStages(
  stages: readonly PipelineStage[],
  decorator: StageLoggerDecorator,
): readonly PipelineStage[] {
  return stages.map((s) => (SILENT_STAGE_IDS.has(s.id) ? s : decorator.wrap(s)));
}
