import {
  Inject,
  Injectable,
  Logger,
  NestMiddleware,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request, Response, NextFunction } from 'express';
import { TypedEvents } from '../shared/typed-events';
import { randomUUID } from 'node:crypto';
import { AuthService } from '../auth/auth.service';
import { TokenRevocationService } from '../auth/token-revocation.service';
import { TrustScoreService } from '../trust-score/trust-score.service';
import { HashcashService } from '../hashcash/hashcash.service';
import { PolicyEvaluatorService } from '../policy/policy-evaluator.service';
import { AUDIT_SIGNAL } from '../policy/policy-events';
import { MfaChallenger, type MfaCreateResult } from '../mfa/mfa-challenger.service';
import { ProxyService } from '../proxy/proxy.service';
import { BoPlaInterceptor } from '../proxy/bopla.interceptor';
import { AuditService } from '../audit/audit.service';
import { AuditExhaustedException } from '../audit/audit-exhausted.exception';
import { MetricsService, type PipelineStage } from '../metrics/metrics.service';
import { HASHCASH_CONFIG, type HashcashConfig } from '../config/slices';
import { extractIp } from '../shared/request-context.util';
import { sleep } from '../shared/sleep.util';
import { PUBLIC_PATHS } from './public-paths';
import { HONEYPOT_PATHS } from '../honeypot/honeypot.constants';
import { PublicBypassStage } from './pipeline/stages/public-bypass.stage';
import { HoneypotBypassStage } from './pipeline/stages/honeypot-bypass.stage';
import { AuthStage } from './pipeline/stages/auth.stage';
import { RevocationStage } from './pipeline/stages/revocation.stage';
import { AuthOnlyShortCircuitStage } from './pipeline/stages/auth-only-shortcircuit.stage';
import { TrustScoreStage } from './pipeline/stages/trust-score.stage';
import { buildStageContext } from './pipeline/build-stage-context';
import type { UserClaims } from '../auth/interfaces/user-claims.interface';
import type { AuditEntry } from '../audit/audit-entry.interface';

/**
 * Phase 10 — GatewayMiddleware (D-01..D-16, GTWY-01..09).
 *
 * Single async function orchestrating the 10-step zero-trust pipeline. Every
 * short-circuit returns explicitly so we never double-respond (Pitfall 4).
 *
 * Stage order: auth -> revocation -> trust_score -> hashcash -> policy ->
 *              [mfa] -> proxy. Audit + metrics fire at terminal decisions.
 *
 * Path dispatch primitives are statically imported (no DI) — see Pitfall 6:
 * importing HoneypotModule would create a DI cycle through FingerprintStore.
 */
@Injectable()
export class GatewayMiddleware implements NestMiddleware {
  private readonly logger = new Logger(GatewayMiddleware.name);

  constructor(
    private readonly auth: AuthService,
    private readonly revocation: TokenRevocationService,
    private readonly trustScore: TrustScoreService,
    private readonly hashcash: HashcashService,
    private readonly policy: PolicyEvaluatorService,
    private readonly mfa: MfaChallenger,
    private readonly proxy: ProxyService,
    private readonly boPla: BoPlaInterceptor,
    private readonly audit: AuditService,
    private readonly metrics: MetricsService,
    @Inject(HASHCASH_CONFIG) private readonly cfg: HashcashConfig,
    private readonly events: TypedEvents,
    private readonly publicBypass: PublicBypassStage,
    private readonly honeypotBypass: HoneypotBypassStage,
    private readonly authStage: AuthStage,
    private readonly revocationStage: RevocationStage,
    private readonly authOnlyStage: AuthOnlyShortCircuitStage,
    private readonly trustScoreStage: TrustScoreStage,
  ) {}

  async use(req: Request, res: Response, next: NextFunction): Promise<void> {
    const requestId = (req.headers['x-request-id'] as string | undefined) ?? randomUUID();
    const ja4h = (req as unknown as Record<string, unknown>)['x-ja4h'] as string | undefined;

    // NestJS `consumer.apply(...).forRoutes('*')` mounts this middleware as a
    // sub-app per matched route, which causes `req.path` to be '/' and the
    // matched route to live in `req.baseUrl`. We therefore derive the request
    // path from `req.originalUrl` (always preserved across nesting) and strip
    // any query string. Falls back to `req.path` for unit tests that pass a
    // bare mock request without `originalUrl`.
    const reqPath: string = (() => {
      const raw = req.originalUrl ?? req.url ?? req.path;
      const q = raw.indexOf('?');
      return q >= 0 ? raw.slice(0, q) : raw;
    })();

    // Phase 12 — F-p — CORS preflight bypass.
    // app.enableCors() (main.ts:36) writes the reply; we just must not 401 here.
    if (req.method === 'OPTIONS') return next();

    // Phase D — PUBLIC bypass via PipelineStage (parallel wire; inline kept
    // as belt-and-braces until Task 14 promotes the orchestrator to sole driver).
    const stageCtx = buildStageContext(req, res, next);
    const publicOutcome = await this.publicBypass.run(stageCtx);
    if (publicOutcome.kind === 'bypass') return next();

    // Phase D — HONEYPOT bypass via PipelineStage (parallel wire).
    const honeypotOutcome = await this.honeypotBypass.run(stageCtx);
    if (honeypotOutcome.kind === 'bypass') return next();

    // D-03 — PUBLIC bypass (GTWY-08)
    if (PUBLIC_PATHS.has(reqPath)) return next();

    // D-05 — HONEYPOT bypass (GTWY-09); ShadowController handles the rest
    if (HONEYPOT_PATHS.has(reqPath)) return next();

    // Per-stage timing (D-14, Pitfall 7): every observe call divides ms by 1000
    // EXPLICITLY at the callsite so reviewers and grep audits can confirm every
    // stage records SECONDS, not milliseconds. The helper takes a t0 and the
    // callsite passes `(Date.now() - t0) / 1000` so the unit conversion lives
    // in the body of `use()` where it is locally auditable.
    const observe = (stage: PipelineStage, seconds: number): void =>
      this.metrics.observeStageDuration(stage, seconds);

    // D-11 — best-effort audit with 200ms cap; on timeout: incrementAuditFailure + warn log
    const TIMEOUT = Symbol('audit_timeout');
    const recordWithTimeout = async (entry: AuditEntry): Promise<void> => {
      const result = await Promise.race<typeof TIMEOUT | 'OK'>([
        this.audit.log(entry).then(() => 'OK' as const),
        sleep(200).then(() => TIMEOUT),
      ]);
      if (result === TIMEOUT) {
        this.metrics.incrementAuditFailure();
        this.logger.warn(
          `audit_timeout requestId=${entry.requestId ?? '?'} decision=${entry.decision}`,
        );
      }
    };

    let claims: UserClaims | undefined;
    let trustScoreValue: number | undefined;

    try {
      // ── Step 5: Auth (Phase D — extracted to AuthStage) ──────────
      let t0 = Date.now();
      const authOutcome = await this.authStage.run(stageCtx);
      observe('auth', (Date.now() - t0) / 1000);
      if (authOutcome.kind === 'short-circuit') {
        res.status(authOutcome.status).json(authOutcome.body);
        return;
      }
      claims = stageCtx.claims!;

      // ── Step 6: Revocation (Phase D — extracted to RevocationStage) ──
      t0 = Date.now();
      const revOutcome = await this.revocationStage.run(stageCtx);
      observe('revocation', (Date.now() - t0) / 1000);
      if (revOutcome.kind === 'short-circuit') {
        res.status(revOutcome.status).json(revOutcome.body);
        return;
      }

      // D-04 — AUTH_ONLY early exit (Phase D — extracted to AuthOnlyShortCircuitStage)
      t0 = Date.now();
      const authOnlyOutcome = await this.authOnlyStage.run(stageCtx);
      // 'auth_only' is a NEW stage label introduced in Phase D; Task 15 widens
      // observeStageDuration to accept string. Cast bridges the union until then.
      observe('auth_only' as PipelineStage, (Date.now() - t0) / 1000);
      if (authOnlyOutcome.kind === 'bypass') return next();

      // ── Step 7: Trust Score (Phase D — extracted to TrustScoreStage) ─
      t0 = Date.now();
      await this.trustScoreStage.run(stageCtx);
      observe('trust_score', (Date.now() - t0) / 1000);
      trustScoreValue = stageCtx.trustScore!;
      const ctx = stageCtx.trustCtx!;

      // ── Step 8: Hashcash (D-08; threshold from HashcashConfig) ───
      t0 = Date.now();
      const hcThreshold = this.cfg.triggerThreshold ?? 0.5;
      if (trustScoreValue > hcThreshold) {
        const nonceHeader = (req.headers['x-hashcash-nonce'] as string | undefined) || '';
        const solutionHeader = (req.headers['x-hashcash-solution'] as string | undefined) || '';

        const issue = (errCode: 'proof_of_work_required' | 'proof_of_work_invalid'): void => {
          const { nonce, difficulty, expiresAt } = this.hashcash.issueChallenge(
            claims.userId,
            claims.deviceId || '',
            trustScoreValue,
          );
          observe('hashcash', (Date.now() - t0) / 1000);
          res
            .status(429)
            .set('X-Hashcash-Challenge', `${nonce}:${difficulty}`)
            .set('Retry-After', '1')
            .json({
              error: errCode,
              nonce,
              difficulty,
              expiresAt,
              requestId,
            });
        };

        if (!nonceHeader || !solutionHeader) {
          issue('proof_of_work_required');
          return;
        }
        if (solutionHeader.length > 256 || solutionHeader.length < 1) {
          issue('proof_of_work_invalid');
          return;
        }
        const r = this.hashcash.verifySolution(
          nonceHeader,
          solutionHeader,
          trustScoreValue,
          claims.userId,
          claims.deviceId || '',
        );
        if (!r.ok) {
          issue('proof_of_work_invalid');
          return;
        }
      }
      observe('hashcash', (Date.now() - t0) / 1000);

      // ── Step 9: Policy ─────────────────────────────────────────────
      t0 = Date.now();
      const decision = await this.policy.evaluate(req);
      observe('policy', (Date.now() - t0) / 1000);

      // ── Step 9b: MFA promotion (D-07) ──────────────────────────────
      if (decision.decision === 'CHALLENGE') {
        t0 = Date.now();
        const mfaToken = req.headers['x-mfa-token'] as string | undefined;
        let promoted = false;
        if (mfaToken) {
          const r = await this.mfa.validateMfaToken(
            mfaToken,
            claims.userId,
            claims.deviceId || '',
            extractIp(req),
            ja4h,
          );
          if (r.ok) {
            this.metrics.incrementMfaPromotion('allow');
            observe('mfa', (Date.now() - t0) / 1000);
            promoted = true;
          }
        }
        if (!promoted) {
          this.metrics.incrementMfaPromotion('reject');
          observe('mfa', (Date.now() - t0) / 1000);
          await recordWithTimeout({
            userId: claims.userId,
            resource: reqPath,
            action: req.method,
            decision: 'challenge',
            trustScore: trustScoreValue,
            ja4hFingerprint: ja4h,
            ipAddress: extractIp(req),
            requestId,
          });
          this.metrics.incrementRequest('challenge');
          const ch = await this.mfa.createChallenge(claims.userId, extractIp(req), ja4h);
          this.buildMfaChallengeResponse(res, ch, requestId);
          return;
        }
      } else if (decision.decision === 'DENY') {
        await recordWithTimeout({
          userId: claims.userId,
          resource: reqPath,
          action: req.method,
          decision: 'deny',
          trustScore: trustScoreValue,
          ja4hFingerprint: ja4h,
          ipAddress: extractIp(req),
          requestId,
        });
        this.metrics.incrementRequest('deny');
        res.status(403).json({
          error: 'policy_denied',
          reason: decision.reason,
          requestId,
        });
        return;
      }

      // ── Step 10: ALLOW path (D-09 audit BEFORE proxy) ──────────────
      const allowEntry: AuditEntry = {
        userId: claims.userId,
        resource: reqPath,
        action: req.method,
        decision: 'allow',
        trustScore: trustScoreValue,
        ja4hFingerprint: ja4h,
        ipAddress: extractIp(req),
        requestId,
      };
      const walT0 = Date.now();
      await this.audit.log(allowEntry); // throws AuditExhaustedException on ALLOW
      this.metrics.observeAuditWalDuration((Date.now() - walT0) / 1000);

      t0 = Date.now();
      const upstreamRes = await this.proxy.forward(req, claims, trustScoreValue);
      observe('proxy', (Date.now() - t0) / 1000);

      // GTWY-06 BOPLA stripping
      const stripped = this.boPla.strip(upstreamRes.data, reqPath, claims.roles ?? []);

      // D-12 / GTWY-05 — trust context only on upstream 2xx
      if (upstreamRes.status < 400) {
        await this.trustScore.recordTrustContextAfterAllow(ctx, trustScoreValue);
      }

      this.metrics.incrementRequest('allow');
      res.status(upstreamRes.status).json(stripped);
      return;
    } catch (e) {
      if (e instanceof AuditExhaustedException) {
        this.metrics.incrementAuditFailure();
        // D-10: emit AUDIT_SIGNAL so ThreatEscalationService aggregates
        this.events.emit(AUDIT_SIGNAL, {
          type: AUDIT_SIGNAL,
          ip: extractIp(req),
          userId: claims?.userId,
          ja4h,
          ts: Date.now(),
          resource: reqPath,
          action: req.method,
          requestId,
        });
        res.status(503).set('Retry-After', '5').json({ error: 'audit_unavailable', requestId });
        return;
      }
      if (e instanceof ServiceUnavailableException) {
        res.status(502).json({ error: 'proxy_unavailable', requestId });
        return;
      }
      if (e instanceof UnauthorizedException) {
        res.status(401).json({ error: 'auth_invalid', message: (e as Error).message, requestId });
        return;
      }
      throw e;
    }
  }

  private buildMfaChallengeResponse(res: Response, ch: MfaCreateResult, requestId: string): void {
    if (ch.ok === false) {
      const reason = ch.reason;
      const status = reason === 'rate_limited' ? 429 : 503;
      res.status(status).json({ error: `mfa_${reason}`, requestId });
      return;
    }
    res
      .status(401)
      .set('WWW-Authenticate', `MFA realm="gateway", challengeId="${ch.challengeId}"`)
      .set('X-MFA-Challenge', ch.challengeId)
      .json({
        error: 'mfa_required',
        challengeId: ch.challengeId,
        verifyEndpoint: '/mfa/verify',
        expiresAt: new Date(ch.expiresAt).toISOString(),
        requestId,
      });
  }
}
