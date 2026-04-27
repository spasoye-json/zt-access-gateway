import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { Enforcer, newEnforcer } from 'casbin';
import { Mutex } from 'async-mutex';
import type { Request } from 'express';
import { AppConfigService } from '../config/config.service';
import { TrustScoreService } from '../trust-score/trust-score.service';
import type { TrustContext } from '../trust-score/trust-context';
import { extractIp, extractJa4h } from '../shared/request-context.util';
import type { UserClaims } from '../auth/interfaces/user-claims.interface';
import {
  buildSubjects,
  normalizeAction,
  normalizeResource,
} from './policy-subject.util';
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
    private readonly cfg: AppConfigService,
    private readonly threat: ThreatEscalationService,
    private readonly trust: TrustScoreService,
    private readonly metrics: PolicyMetrics,
    private readonly events: EventEmitter2,
  ) {}

  /**
   * D-03 startup fail-closed: any throw propagates to bootstrap → process aborts.
   * Refuses to start if model.conf or policy.csv are unreadable / malformed.
   */
  async onModuleInit(): Promise<void> {
    // prettier-ignore
    this.enforcer = await newEnforcer(this.cfg.policyModelPath, this.cfg.policyCsvPath);
    this.logger.log(
      `Casbin enforcer ready (model=${this.cfg.policyModelPath}, csv=${this.cfg.policyCsvPath})`,
    );
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

    // 2) Subject + obj + act (D-04, D-06, D-07) — computed before score so
    // we can emit a well-formed DENY signal if trust scoring throws (CR-01).
    const subjects = buildSubjects(user);
    const obj = normalizeResource(req.path);
    const act = normalizeAction(req.method);

    // 1) D-09 score seam — mirrors hashcash.guard.ts lines 60-71 verbatim.
    // CR-01: wrap fallback to honor the "never throws on policy paths"
    // contract — TrustScoreService.evaluateScore() can hit DB/repo and
    // throw; surfacing that as a 500 bypasses metrics + policy.deny emit
    // and looks like infra failure to the client. Fail closed instead.
    let score: number;
    try {
      const provided = (req as Request & { trustScore?: number }).trustScore;
      if (provided !== undefined) {
        score = provided;
      } else {
        const ctx: TrustContext = {
          userId: user.userId,
          deviceId: user.deviceId ?? '',
          ip: extractIp(req),
          ja4h: extractJa4h(req) ?? '',
        };
        score = await this.trust.evaluateScore(ctx);
      }
    } catch (err) {
      this.metrics.errors.inc();
      this.logger.warn(`trust-score error: ${(err as Error).message}`);
      this.metrics.decisions.inc({ decision: 'deny' });
      this.emitDeny(req, user, obj, act);
      return { decision: 'DENY', reason: 'policy_error', score: 1 };
    }

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
      this.emitDeny(req, user, obj, act);
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
        matchedSubject: matchedSubject!,
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
      decision: decision.decision.toLowerCase() as
        | 'allow'
        | 'challenge'
        | 'deny',
    });
    if (decision.decision === 'DENY') {
      this.emitDeny(req, user, obj, act);
    }

    return decision;
  }

  /**
   * D-14: every DENY decision emits a `policy.deny` ThreatSignalPayload onto
   * the event bus. ThreatEscalationService subscribes (Plan 03) and feeds
   * into the sliding window aggregator.
   *
   * WR-07: dropped the unused _score parameter — ThreatSignalPayload has no
   * score field. If a future revision adds one, weight signals by score by
   * adding it to the payload schema and threading it through here.
   */
  private emitDeny(
    req: Request,
    user: UserClaims,
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
   *
   * WR-03: when persistence fails (false return OR throw from disk I/O),
   * roll back the in-memory mutation so the enforcer's RAM state stays in
   * sync with disk. Without rollback, subsequent enforce() calls treat the
   * un-persisted rule as authoritative until process restart.
   */
  async addRule(sub: string, obj: string, act: string): Promise<boolean> {
    return this.writerMutex.runExclusive(async () => {
      const added = await this.enforcer.addPolicy(sub, obj, act);
      if (!added) return false;
      try {
        const saved = await this.enforcer.savePolicy();
        if (!saved) {
          await this.enforcer.removePolicy(sub, obj, act).catch(() => {});
          throw new Error(
            'savePolicy returned false — check policy/model.conf has [role_definition]',
          );
        }
        return true;
      } catch (err) {
        // Defensive: if savePolicy threw (e.g. EIO), undo the in-memory add.
        // .catch swallows secondary failures so we always propagate the
        // original persistence error to the caller.
        await this.enforcer.removePolicy(sub, obj, act).catch(() => {});
        throw err;
      }
    });
  }

  /**
   * D-22: serialized through writer mutex (D-02). Same Pitfall 1 hardening
   * as addRule. WR-03: symmetric rollback — re-add the rule if persistence
   * fails so memory stays consistent with disk.
   */
  async removeRule(sub: string, obj: string, act: string): Promise<boolean> {
    return this.writerMutex.runExclusive(async () => {
      const removed = await this.enforcer.removePolicy(sub, obj, act);
      if (!removed) return false;
      try {
        const saved = await this.enforcer.savePolicy();
        if (!saved) {
          await this.enforcer.addPolicy(sub, obj, act).catch(() => {});
          throw new Error(
            'savePolicy returned false — check policy/model.conf has [role_definition]',
          );
        }
        return true;
      } catch (err) {
        await this.enforcer.addPolicy(sub, obj, act).catch(() => {});
        throw err;
      }
    });
  }
}
