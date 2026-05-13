import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { TypedEvents } from '../shared/typed-events';
import { Enforcer, newEnforcer } from 'casbin';
import { Mutex } from 'async-mutex';
import type { Request } from 'express';
import { POLICY_CONFIG, type PolicyConfig } from '../config/slices';
import { TrustScoreService } from '../trust-score/trust-score.service';
import type { TrustContext } from '../trust-score/trust-context';
import { extractIp, extractJa4h } from '../shared/request-context.util';
import type { UserClaims } from '../auth/interfaces/user-claims.interface';
import { buildSubjects, normalizeAction, normalizeResource } from './policy-subject.util';
import type { PolicyDecision } from './policy-decision';
import { POLICY_DENY, type ThreatSignalPayload } from './policy-events';
import { PolicyMetrics } from './policy-metrics';
import { ThreatEscalationService } from './threat-escalation.service';

/**
 * Phase 6 — PolicyEvaluatorService (D-01, D-02, D-03, D-04..D-10).
 *
 * Casbin enforcer (singleton, file-backed) + fail-closed runtime evaluate()
 * + score-seam (req.trustScore-first, fallback to TrustScoreService) +
 * writer-mutex-protected admin mutators (addRule / removeRule).
 *
 * NEVER throws on policy/Casbin paths — returns DENY with reason
 * 'policy_error' instead. Closes PITFALLS "Casbin defaults to ALLOW on
 * enforcer error".
 *
 * Note (D-12): HASHCASH_TRIGGER_THRESHOLD (Phase 5, pipeline step 7) gates
 * whether PoW is required; POLICY_CHALLENGE_THRESHOLD (this service, step
 * 8) gates ALLOW/CHALLENGE. The two are independent — no coupling.
 */
@Injectable()
export class PolicyEvaluatorService implements OnModuleInit {
  private readonly logger = new Logger(PolicyEvaluatorService.name);
  private enforcer!: Enforcer;
  private readonly writerMutex = new Mutex();

  constructor(
    @Inject(POLICY_CONFIG) private readonly cfg: PolicyConfig,
    private readonly threat: ThreatEscalationService,
    private readonly trust: TrustScoreService,
    private readonly metrics: PolicyMetrics,
    private readonly events: TypedEvents,
  ) {}

  /**
   * D-03 startup fail-closed: any throw propagates to bootstrap → process aborts.
   * Refuses to start if model.conf or policy.csv are unreadable / malformed.
   */
  async onModuleInit(): Promise<void> {
    // prettier-ignore
    this.enforcer = await newEnforcer(this.cfg.modelPath, this.cfg.csvPath);
    this.logger.log(`Casbin enforcer ready (model=${this.cfg.modelPath}, csv=${this.cfg.csvPath})`);
  }

  /**
   * Evaluate one request. Returns ALLOW/CHALLENGE/DENY per D-10 mapping.
   *
   * Score seam (D-09): req.trustScore consumed first; falls back to
   * TrustScoreService.evaluateScore(ctx) when undefined. Phase 10
   * GatewayMiddleware will populate req.trustScore once before policy runs.
   *
   * Anti-throw: the only place evaluate() may surface a throw is from
   * non-policy bugs (e.g., extractIp itself bombs) — the Casbin path is
   * fully wrapped and returns DENY policy_error.
   */
  async evaluate(req: Request): Promise<PolicyDecision> {
    const user = (req as Request & { user?: UserClaims }).user;
    if (!user) {
      // Defensive — JwtAuthGuard should have attached user; treat as DENY.
      return { decision: 'DENY', reason: 'no_user', score: 1 };
    }

    // 1) D-09 score seam — mirrors hashcash.guard.ts lines 60-71 verbatim.
    let score = (req as Request & { trustScore?: number }).trustScore;
    if (score === undefined) {
      const ctx: TrustContext = {
        userId: user.userId,
        deviceId: user.deviceId ?? '',
        ip: extractIp(req),
        ja4h: extractJa4h(req) ?? '',
      };
      score = await this.trust.evaluateScore(ctx);
    }

    // 2) Subject + obj + act (D-04, D-06, D-07).
    const subjects = buildSubjects(user);
    const obj = normalizeResource(req.path);
    const act = normalizeAction(req.method);

    // 3) Casbin (fail-closed runtime per D-03 / RESEARCH Pitfall 2).
    let casbinAllow = false;
    let matchedSubject: string | undefined;
    try {
      for (const sub of subjects) {
        if (await this.enforcer.enforce(sub, obj, act)) {
          casbinAllow = true;
          matchedSubject = sub;
          break;
        }
      }
    } catch (err) {
      this.metrics.errors.inc();
      this.logger.warn(`policy enforcer error: ${(err as Error).message}`);
      const denyDecision: PolicyDecision = {
        decision: 'DENY',
        reason: 'policy_error',
        score,
      };
      this.metrics.decisions.inc({ decision: 'deny' });
      this.emitDeny(req, user, score, obj, act);
      return denyDecision;
    }

    // 4) Live thresholds (D-21).
    const challengeT = this.threat.currentChallengeThreshold();
    const denyT = this.threat.currentDenyThreshold();

    // 5) D-10 mapping. Casbin DENY (no rule matches) wins over a low score.
    let decision: PolicyDecision;
    if (!casbinAllow) {
      decision = { decision: 'DENY', reason: 'casbin_no_match', score };
    } else if (score >= denyT) {
      decision = {
        decision: 'DENY',
        reason: 'score_above_deny_threshold',
        score,
        matchedSubject,
      };
    } else if (score < challengeT) {
      decision = {
        decision: 'ALLOW',
        reason: 'score_below_challenge_threshold',
        score,
        matchedSubject: matchedSubject,
      };
    } else {
      decision = {
        decision: 'CHALLENGE',
        reason: 'score_in_challenge_band',
        score,
        matchedSubject,
      };
    }

    // 6) Side effects: metrics + event emit on DENY (D-14).
    this.metrics.decisions.inc({
      decision: decision.decision.toLowerCase(),
    });
    if (decision.decision === 'DENY') {
      this.emitDeny(req, user, score, obj, act);
    }

    return decision;
  }

  /**
   * D-14: every DENY decision emits a `policy.deny` ThreatSignalPayload onto
   * the event bus. ThreatEscalationService subscribes (Plan 03) and feeds
   * into the sliding window aggregator.
   */
  private emitDeny(
    req: Request,
    user: UserClaims,
    _score: number,
    resource: string,
    action: string,
  ): void {
    const payload: ThreatSignalPayload = {
      type: POLICY_DENY,
      ip: extractIp(req),
      userId: user.userId,
      ja4h: extractJa4h(req),
      ts: Date.now(),
      resource,
      action,
    };
    this.events.emit(POLICY_DENY, payload);
  }

  /**
   * Introspection — returns all p-rules currently in the enforcer's memory.
   * Lock-free read (D-02).
   */
  async getRules(): Promise<string[][]> {
    return this.enforcer.getPolicy();
  }

  /**
   * D-22: serialized through writer mutex (D-02). Pitfall 1 hardening:
   * savePolicy() returning false means model.conf lacks [role_definition]
   * and the CSV did not actually persist — surface as a runtime error so
   * operators learn at the first admin write rather than after a restart.
   */
  async addRule(sub: string, obj: string, act: string): Promise<boolean> {
    return this.writerMutex.runExclusive(async () => {
      const added = await this.enforcer.addPolicy(sub, obj, act);
      if (added) {
        const saved = await this.enforcer.savePolicy();
        if (!saved) {
          throw new Error(
            'savePolicy returned false — check policy/model.conf has [role_definition]',
          );
        }
      }
      return added;
    });
  }

  /**
   * D-22: serialized through writer mutex (D-02). Same Pitfall 1 hardening
   * as addRule.
   */
  async removeRule(sub: string, obj: string, act: string): Promise<boolean> {
    return this.writerMutex.runExclusive(async () => {
      const removed = await this.enforcer.removePolicy(sub, obj, act);
      if (removed) {
        const saved = await this.enforcer.savePolicy();
        if (!saved) {
          throw new Error(
            'savePolicy returned false — check policy/model.conf has [role_definition]',
          );
        }
      }
      return removed;
    });
  }
}
