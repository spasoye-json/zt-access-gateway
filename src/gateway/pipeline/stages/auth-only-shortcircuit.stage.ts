import { Injectable, Logger } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { isAuthOnlyPath } from '../../public-paths';
import { AuditService } from '../../../audit/audit.service';
import { MetricsService } from '../../../metrics/metrics.service';
import { extractIp } from '../../../shared/request-context.util';
import { recordWithTimeoutBestEffort } from '../record-with-timeout.util';

/**
 * Phase D Stage 5 — AUTH_ONLY early exit (D-04 / WR-03).
 *
 * Paths registered in AUTH_ONLY_EXACT / AUTH_ONLY_PREFIXES finish their
 * pipeline traversal here: best-effort audit `allow` (200ms timeout) then
 * `bypass` to invoke `next()`. trustScore intentionally omitted from the
 * AuditEntry (Pitfall 2 — no score evaluated for AUTH_ONLY).
 */
@Injectable()
export class AuthOnlyShortCircuitStage implements PipelineStage {
  readonly id = 'auth_only';
  private readonly logger = new Logger(AuthOnlyShortCircuitStage.name);

  constructor(
    private readonly audit: AuditService,
    private readonly metrics: MetricsService,
  ) {}

  async run(ctx: StageContext): Promise<StageOutcome> {
    if (!isAuthOnlyPath(ctx.reqPath)) {
      return { kind: 'continue' };
    }
    if (!ctx.claims) {
      throw new Error('AuthOnlyShortCircuitStage: ctx.claims missing');
    }
    await recordWithTimeoutBestEffort(this.audit, this.metrics, this.logger, {
      userId: ctx.claims.userId,
      resource: ctx.reqPath,
      action: ctx.req.method,
      decision: 'allow',
      ja4hFingerprint: ctx.ja4h,
      ipAddress: extractIp(ctx.req),
      requestId: ctx.requestId,
      // trustScore intentionally omitted (Pitfall 2)
    });
    return { kind: 'bypass' };
  }
}
