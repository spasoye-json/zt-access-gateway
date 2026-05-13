import { Injectable } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { AuditService } from '../../../audit/audit.service';
import { MetricsService } from '../../../metrics/metrics.service';
import { extractIp } from '../../../shared/request-context.util';
import type { AuditEntry } from '../../../audit/audit-entry.interface';

/**
 * Phase D Stage 10 — Fail-closed ALLOW audit BEFORE proxy (D-09).
 *
 * Unlike CHALLENGE/DENY/AUTH_ONLY audits (best-effort with timeout), the
 * ALLOW audit is fail-closed: `audit.log(entry)` may throw
 * AuditExhaustedException, which propagates up to `handleTerminalError` and
 * surfaces as 503 audit_unavailable + Retry-After:5. The proxy MUST NOT be
 * called when the audit trail cannot be persisted.
 *
 * Also records audit_wal_duration timing on success.
 */
@Injectable()
export class AuditAllowStage implements PipelineStage {
  readonly id = 'audit_allow';

  constructor(
    private readonly audit: AuditService,
    private readonly metrics: MetricsService,
  ) {}

  async run(ctx: StageContext): Promise<StageOutcome> {
    if (!ctx.claims) throw new Error('AuditAllowStage: ctx.claims missing');
    const allowEntry: AuditEntry = {
      userId: ctx.claims.userId,
      resource: ctx.reqPath,
      action: ctx.req.method,
      decision: 'allow',
      trustScore: ctx.trustScore,
      ja4hFingerprint: ctx.ja4h,
      ipAddress: extractIp(ctx.req),
      requestId: ctx.requestId,
    };
    const walT0 = Date.now();
    await this.audit.log(allowEntry); // throws AuditExhaustedException on WAL exhaustion
    this.metrics.observeAuditWalDuration((Date.now() - walT0) / 1000);
    return { kind: 'continue' };
  }
}
