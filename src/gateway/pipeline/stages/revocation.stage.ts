import { Injectable, Logger } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { TokenRevocationService } from '../../../auth/token-revocation.service';
import { AuditService } from '../../../audit/audit.service';
import { MetricsService } from '../../../metrics/metrics.service';
import { extractIp } from '../../../shared/request-context.util';
import { recordWithTimeoutBestEffort } from '../record-with-timeout.util';

/**
 * Slice F (#7) — denies replay of self-revoked JWTs.
 *
 * Runs immediately after AuthStage so `ctx.claims.jti` is populated. Skips
 * (continues) when claims are absent — public/bypassed paths reach this stage
 * only by structural accident. On a revoked jti, writes a single best-effort
 * audit row tagged `eventType: 'REVOCATION_BLOCKED'` (precedent: AUDT-06's
 * 'HONEYPOT_TRIGGERED') and short-circuits 401 `token_revoked`. The
 * `'revocation'` detail builder in default-detail-builders.ts surfaces the jti
 * in the per-request log line: `revocation  ✗ DENY  jti=...`.
 */
@Injectable()
export class RevocationStage implements PipelineStage {
  readonly id = 'revocation';
  private readonly logger = new Logger(RevocationStage.name);

  constructor(
    private readonly revocation: TokenRevocationService,
    private readonly audit: AuditService,
    private readonly metrics: MetricsService,
  ) {}

  async run(ctx: StageContext): Promise<StageOutcome> {
    const claims = ctx.claims;
    if (!claims) return { kind: 'continue' };
    if (!this.revocation.isRevoked(claims.jti)) return { kind: 'continue' };

    await recordWithTimeoutBestEffort(this.audit, this.metrics, this.logger, {
      userId: claims.userId,
      resource: ctx.reqPath,
      action: ctx.req.method,
      decision: 'deny',
      eventType: 'REVOCATION_BLOCKED',
      ja4hFingerprint: ctx.ja4h,
      ipAddress: extractIp(ctx.req),
      requestId: ctx.requestId,
    });
    return {
      kind: 'short-circuit',
      status: 401,
      body: { error: 'token_revoked', requestId: ctx.requestId },
    };
  }
}
