import {
  Injectable,
  Logger,
  NestMiddleware,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import type { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'node:crypto';
import { AuthService } from '../auth/auth.service';
import { TokenRevocationService } from '../auth/token-revocation.service';
import { TrustScoreService } from '../trust-score/trust-score.service';
import { HashcashService } from '../hashcash/hashcash.service';
import { PolicyEvaluatorService } from '../policy/policy-evaluator.service';
import { AUDIT_SIGNAL, AUTH_INVALID_TOKEN } from '../policy/policy-events';
import { MfaService, type MfaCreateResult } from '../mfa/mfa.service';
import { ProxyService } from '../proxy/proxy.service';
import { BoPlaInterceptor } from '../proxy/bopla.interceptor';
import { AuditService } from '../audit/audit.service';
import { AuditExhaustedException } from '../audit/audit-exhausted.exception';
import { MetricsService, type PipelineStage } from '../metrics/metrics.service';
import { AppConfigService } from '../config/config.service';
import { extractIp } from '../shared/request-context.util';
import { sleep } from '../shared/sleep.util';
import { PUBLIC_PATHS, isAuthOnlyPath } from './public-paths';
import { HONEYPOT_PATHS } from '../honeypot/honeypot.constants';
import type { UserClaims, AuthenticatedClaims } from '../auth/interfaces/user-claims.interface';
import type { TrustContext } from '../trust-score/trust-context';
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
    private readonly mfa: MfaService,
    private readonly proxy: ProxyService,
    private readonly boPla: BoPlaInterceptor,
    private readonly audit: AuditService,
    private readonly metrics: MetricsService,
    private readonly cfg: AppConfigService,
    private readonly events: EventEmitter2,
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

    // WR-01: D-14 contract — every auth failure must publish AUTH_INVALID_TOKEN
    // so ThreatEscalationService aggregates consistently regardless of whether
    // the route is gateway-mounted or hits JwtAuthGuard directly. Mirror the
    // payload shape used by JwtAuthGuard.emitInvalid.
    const emitAuthInvalid = (): void => {
      this.events.emit(AUTH_INVALID_TOKEN, {
        type: AUTH_INVALID_TOKEN,
        ip: extractIp(req),
        userId: claims?.userId,
        ja4h,
        ts: Date.now(),
      });
    };

    try {
      // ── Step 5: Auth ───────────────────────────────────────────────
      let t0 = Date.now();
      const authHeader = req.headers['authorization'];
      if (!authHeader || typeof authHeader !== 'string') {
        observe('auth', (Date.now() - t0) / 1000);
        emitAuthInvalid();
        res.status(401).json({ error: 'auth_required', requestId });
        return;
      }
      const [scheme, token] = authHeader.split(' ');
      if (scheme !== 'Bearer' || !token) {
        observe('auth', (Date.now() - t0) / 1000);
        emitAuthInvalid();
        res.status(401).json({ error: 'auth_required', requestId });
        return;
      }
      try {
        claims = await this.auth.validateToken(token);
      } catch (e) {
        observe('auth', (Date.now() - t0) / 1000);
        if (e instanceof UnauthorizedException) {
          emitAuthInvalid();
          res.status(401).json({
            error: 'auth_invalid',
            message: (e as Error).message,
            requestId,
          });
          return;
        }
        throw e;
      }
      observe('auth', (Date.now() - t0) / 1000);

      // ── Step 6: Revocation ─────────────────────────────────────────
      t0 = Date.now();
      if (this.revocation.isRevoked(claims.jti)) {
        observe('revocation', (Date.now() - t0) / 1000);
        res.status(401).json({ error: 'token_revoked', requestId });
        return;
      }
      observe('revocation', (Date.now() - t0) / 1000);

      // Phase A2 — single post-revocation assignment of branded claims.
      // D-08 ordering preserved: the brand is only attached AFTER isRevoked()
      // clears. Collapses the prior two-write pattern (req.user = claims +
      // sentinel symbol) into one branded assignment that the guard reads via
      // property-presence on `__authenticatedByGateway`.
      (req as Request & { user?: UserClaims | AuthenticatedClaims }).user = {
        ...claims,
        __authenticatedByGateway: true,
      };

      // D-04 — AUTH_ONLY early exit (audit allow, then next())
      // WR-03: wrap in recordWithTimeout so a hung Postgres insert cannot
      // block /auth/revoke, /mfa/*, /policy/admin/*, /audit/logs — exactly
      // the routes hit during a security incident. Best-effort audit is the
      // documented contract (CLAUDE.md: "Audit logging is best-effort").
      if (isAuthOnlyPath(reqPath)) {
        await recordWithTimeout({
          userId: claims.userId,
          resource: reqPath,
          action: req.method,
          decision: 'allow',
          ja4hFingerprint: ja4h,
          ipAddress: extractIp(req),
          requestId,
          // trustScore intentionally omitted (Pitfall 2 — no score evaluated)
        });
        return next();
      }

      // ── Step 7: Trust Score (D-13 — set once) ──────────────────────
      t0 = Date.now();
      const ctx: TrustContext = {
        userId: claims.userId,
        deviceId: claims.deviceId || '',
        ip: extractIp(req),
        ja4h: ja4h ?? '',
      };
      trustScoreValue = await this.trustScore.evaluateScore(ctx);
      (req as Request & { trustScore?: number }).trustScore = trustScoreValue;
      observe('trust_score', (Date.now() - t0) / 1000);

      // ── Step 8: Hashcash (D-08; threshold from AppConfigService) ───
      t0 = Date.now();
      const hcThreshold = this.cfg.hashcashTriggerThreshold ?? 0.5;
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
