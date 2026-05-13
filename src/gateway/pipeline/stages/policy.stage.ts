import { Injectable } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { PolicyEvaluatorService } from '../../../policy/policy-evaluator.service';

/**
 * Phase D Stage 8 — Casbin RBAC policy evaluation.
 *
 * Pure setter: calls PolicyEvaluatorService.evaluate(req) and stashes the
 * PolicyDecision on `ctx.policyDecision`. Branching on ALLOW / CHALLENGE /
 * DENY happens in the downstream MfaPromotionStage (Task 11) — keeping this
 * stage as a single-responsibility setter makes the test surface trivial
 * (1 mock).
 */
@Injectable()
export class PolicyStage implements PipelineStage {
  readonly id = 'policy';

  constructor(private readonly policy: PolicyEvaluatorService) {}

  async run(ctx: StageContext): Promise<StageOutcome> {
    ctx.policyDecision = await this.policy.evaluate(ctx.req);
    return { kind: 'continue' };
  }
}
