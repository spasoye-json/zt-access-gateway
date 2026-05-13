import { Injectable, Logger } from '@nestjs/common';
import type { PipelineStage, StageOutcome } from '../pipeline-stage';
import type { StageContext } from '../stage-context';
import { MfaChallenger, type MfaCreateResult } from '../../../mfa/mfa-challenger.service';
import { AuditService } from '../../../audit/audit.service';
import { MetricsService } from '../../../metrics/metrics.service';
import { extractIp } from '../../../shared/request-context.util';
import { recordWithTimeoutBestEffort } from '../record-with-timeout.util';

/**
 * Phase D Stage 9 — MFA promotion / policy DENY response (D-07).
 *
 * Consolidates the inline post-policy branching. Handles three input
 * decisions:
 *   - ALLOW     → continue
 *   - DENY      → audit deny + 403 policy_denied short-circuit
 *   - CHALLENGE → validate X-MFA-Token; on valid promote to allow (continue);
 *                 on missing/invalid create a new challenge and short-circuit
 *                 with 401 mfa_required (or 429/503 if challenge creation
 *                 fails — see buildMfaChallengeResponse)
 *
 * id consolidates the old `mfa` label.
 */
@Injectable()
export class MfaPromotionStage implements PipelineStage {
  readonly id = 'mfa_promotion';
  private readonly logger = new Logger(MfaPromotionStage.name);

  constructor(
    private readonly mfa: MfaChallenger,
    private readonly audit: AuditService,
    private readonly metrics: MetricsService,
  ) {}

  async run(ctx: StageContext): Promise<StageOutcome> {
    if (!ctx.claims) throw new Error('MfaPromotionStage: ctx.claims missing');
    if (!ctx.policyDecision) {
      throw new Error('MfaPromotionStage: ctx.policyDecision missing');
    }
    const claims = ctx.claims;
    const decision = ctx.policyDecision;
    const trustScoreValue = ctx.trustScore;

    if (decision.decision === 'ALLOW') {
      return { kind: 'continue' };
    }

    if (decision.decision === 'DENY') {
      await recordWithTimeoutBestEffort(this.audit, this.metrics, this.logger, {
        userId: claims.userId,
        resource: ctx.reqPath,
        action: ctx.req.method,
        decision: 'deny',
        trustScore: trustScoreValue,
        ja4hFingerprint: ctx.ja4h,
        ipAddress: extractIp(ctx.req),
        requestId: ctx.requestId,
      });
      this.metrics.incrementRequest('deny');
      return {
        kind: 'short-circuit',
        status: 403,
        body: {
          error: 'policy_denied',
          reason: decision.reason,
          requestId: ctx.requestId,
        },
      };
    }

    // CHALLENGE: try MFA token; on valid → promote; else issue challenge.
    const mfaToken = ctx.req.headers['x-mfa-token'] as string | undefined;
    if (mfaToken) {
      const r = await this.mfa.validateMfaToken(
        mfaToken,
        claims.userId,
        claims.deviceId || '',
        extractIp(ctx.req),
        ctx.ja4h,
      );
      if (r.ok) {
        this.metrics.incrementMfaPromotion('allow');
        return { kind: 'continue' };
      }
    }
    this.metrics.incrementMfaPromotion('reject');
    await recordWithTimeoutBestEffort(this.audit, this.metrics, this.logger, {
      userId: claims.userId,
      resource: ctx.reqPath,
      action: ctx.req.method,
      decision: 'challenge',
      trustScore: trustScoreValue,
      ja4hFingerprint: ctx.ja4h,
      ipAddress: extractIp(ctx.req),
      requestId: ctx.requestId,
    });
    this.metrics.incrementRequest('challenge');
    const ch = await this.mfa.createChallenge(claims.userId, extractIp(ctx.req), ctx.ja4h);
    return this.buildMfaChallengeOutcome(ch, ctx.requestId);
  }

  private buildMfaChallengeOutcome(ch: MfaCreateResult, requestId: string): StageOutcome {
    if (ch.ok === false) {
      const reason = ch.reason;
      const status = reason === 'rate_limited' ? 429 : 503;
      return {
        kind: 'short-circuit',
        status,
        body: { error: `mfa_${reason}`, requestId },
      };
    }
    return {
      kind: 'short-circuit',
      status: 401,
      body: {
        error: 'mfa_required',
        challengeId: ch.challengeId,
        verifyEndpoint: '/mfa/verify',
        expiresAt: new Date(ch.expiresAt).toISOString(),
        requestId,
      },
      headers: {
        'WWW-Authenticate': `MFA realm="gateway", challengeId="${ch.challengeId}"`,
        'X-MFA-Challenge': ch.challengeId,
      },
    };
  }
}
