/**
 * Phase D — DI token for the ordered list of PipelineStage providers.
 *
 * GatewayModule provides this as a factory that gathers every stage class in
 * the canonical pipeline order; PipelineOrchestrator injects it via
 * `@Inject(PIPELINE_STAGES)`. Adding a new stage is one file + one entry in
 * that provider array — no edits elsewhere.
 */
export const PIPELINE_STAGES = Symbol('PIPELINE_STAGES');
