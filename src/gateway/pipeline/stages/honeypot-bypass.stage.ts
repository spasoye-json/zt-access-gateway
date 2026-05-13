import { Injectable } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { HONEYPOT_PATHS } from '../../../honeypot/honeypot.constants';

/**
 * Phase D Stage 2 — HONEYPOT bypass (D-05 / GTWY-09).
 *
 * Honeypot routes are handled by ShadowController; the pipeline bypasses
 * them. Pitfall 6 preserved: HONEYPOT_PATHS is imported statically (not via
 * DI) to avoid the GatewayModule→HoneypotModule→FingerprintStore cycle.
 */
@Injectable()
export class HoneypotBypassStage implements PipelineStage {
  readonly id = 'honeypot_bypass';

  run(ctx: StageContext): Promise<StageOutcome> {
    return Promise.resolve(
      HONEYPOT_PATHS.has(ctx.reqPath) ? { kind: 'bypass' } : { kind: 'continue' },
    );
  }
}
