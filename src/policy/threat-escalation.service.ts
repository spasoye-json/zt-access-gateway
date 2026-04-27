import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { OnEvent } from '@nestjs/event-emitter';
import { AppConfigService } from '../config/config.service';
import {
  AUDIT_SIGNAL,
  AUTH_INVALID_TOKEN,
  HONEYPOT_TRIGGER,
  MFA_FAILED,
  POLICY_DENY,
  type ThreatSignalPayload,
} from './policy-events';
import { PolicyMetrics } from './policy-metrics';

/**
 * Phase 6 — ThreatEscalationService (Plan 03).
 *
 * Sliding-window aggregator + level state-machine + manual override.
 * Subscribes to all 5 threat-signal event names from day one (D-13, D-14);
 * emitters in Phase 6 wire `policy.deny`, `auth.invalid_token`, and
 * `honeypot.trigger`. `mfa.failed` (Phase 7) and `audit.signal` (Phase 9)
 * land later — silent until then.
 *
 * Key invariants:
 *  - D-18: bounded sliding window; lazy eviction; no timers.
 *  - D-19: per-signal-type counts; effective level = max across types.
 *  - D-20: linear cooldown driven by reads, not timers; new signals reset
 *    the cooldown timer (`lastSignalAt`).
 *  - D-21: live threshold getters consumed by PolicyEvaluatorService.
 *  - D-22: manual override is sticky; auto-aggregation suspended while set.
 *  - Pitfall 8 closure: clock is injectable via THREAT_CLOCK so tests can
 *    drive cooldown deterministically without `jest.useFakeTimers`.
 */

export type ThreatLevel = 'Normal' | 'Elevated' | 'Critical';

type SignalType =
  | typeof POLICY_DENY
  | typeof AUTH_INVALID_TOKEN
  | typeof HONEYPOT_TRIGGER
  | typeof MFA_FAILED
  | typeof AUDIT_SIGNAL;

interface WindowEvent {
  ts: number;
  type: SignalType;
}

/**
 * Token + symbol for an injectable clock — enables deterministic tests
 * (Pitfall 8). Production binds `() => Date.now()`; tests pass a controllable
 * counter through the constructor directly.
 */
export const THREAT_CLOCK = Symbol('THREAT_CLOCK');
export type ClockFn = () => number;

@Injectable()
export class ThreatEscalationService {
  private readonly logger = new Logger(ThreatEscalationService.name);
  private readonly events: WindowEvent[] = [];
  private level: ThreatLevel = 'Normal';
  private lastTransitionAt: number;
  private lastSignalAt: number;
  private manualOverride: ThreatLevel | null = null;
  private readonly clock: ClockFn;

  constructor(
    private readonly cfg: AppConfigService,
    private readonly metrics: PolicyMetrics,
    @Optional() @Inject(THREAT_CLOCK) clock?: ClockFn,
  ) {
    this.clock = clock ?? ((): number => Date.now());
    const now = this.clock();
    this.lastTransitionAt = now;
    this.lastSignalAt = now;
    this.metrics.setThreatLevel('normal');
  }

  // ── Subscribers (D-13, D-14) ──

  @OnEvent(POLICY_DENY)
  onPolicyDeny(p: ThreatSignalPayload): void {
    this.record(POLICY_DENY, p);
  }

  @OnEvent(AUTH_INVALID_TOKEN)
  onAuthInvalidToken(p: ThreatSignalPayload): void {
    this.record(AUTH_INVALID_TOKEN, p);
  }

  @OnEvent(HONEYPOT_TRIGGER)
  onHoneypotTrigger(p: ThreatSignalPayload): void {
    this.record(HONEYPOT_TRIGGER, p);
  }

  @OnEvent(MFA_FAILED)
  onMfaFailed(p: ThreatSignalPayload): void {
    this.record(MFA_FAILED, p);
  }

  @OnEvent(AUDIT_SIGNAL)
  onAuditSignal(p: ThreatSignalPayload): void {
    this.record(AUDIT_SIGNAL, p);
  }

  // ── Read API consumed by PolicyEvaluatorService (D-21) ──

  currentChallengeThreshold(): number {
    this.maybeCooldown();
    switch (this.effectiveLevel()) {
      case 'Critical':
        return this.cfg.policyCriticalChallengeThreshold;
      case 'Elevated':
        return this.cfg.policyElevatedChallengeThreshold;
      default:
        return this.cfg.policyChallengeThreshold;
    }
  }

  currentDenyThreshold(): number {
    this.maybeCooldown();
    switch (this.effectiveLevel()) {
      case 'Critical':
        return this.cfg.policyCriticalDenyThreshold;
      case 'Elevated':
        return this.cfg.policyElevatedDenyThreshold;
      default:
        return this.cfg.policyDenyThreshold;
    }
  }

  // ── Admin API (PLCY-11, D-22) ──

  setManualLevel(level: ThreatLevel): void {
    this.manualOverride = level;
    // If the override matches the current auto level, skip transitionTo so the
    // transitions counter does not record a no-op (Normal → Normal). The
    // override flag is still recorded for snapshot()/audit purposes.
    if (this.level === level) return;
    this.transitionTo(level, this.clock(), /*manual=*/ true);
  }

  clearManualLevel(): void {
    this.manualOverride = null;
    // Re-engage cooldown FIRST so a long-idle override can step down through
    // the normal cooldown ladder, then recompute against any queued signals
    // (which may push the level back up if thresholds are still hit).
    this.maybeCooldown();
    this.recomputeLevel(this.clock());
  }

  snapshot(): {
    level: ThreatLevel;
    since: number;
    signalCounts: Record<string, number>;
    activeThresholds: { challenge: number; deny: number };
    override: ThreatLevel | null;
  } {
    return {
      level: this.effectiveLevel(),
      since: this.lastTransitionAt,
      signalCounts: this.countByType(),
      activeThresholds: {
        challenge: this.currentChallengeThreshold(),
        deny: this.currentDenyThreshold(),
      },
      override: this.manualOverride,
    };
  }

  // ── Internal ──

  private record(type: SignalType, _p: ThreatSignalPayload): void {
    const now = this.clock();
    this.events.push({ ts: now, type });
    // Hard cap (D-18): prevent unbounded growth
    if (this.events.length > this.cfg.threatWindowMaxEvents) {
      this.events.splice(
        0,
        this.events.length - this.cfg.threatWindowMaxEvents,
      );
    }
    this.evict(now);
    this.lastSignalAt = now;
    this.recomputeLevel(now);
  }

  private evict(now: number): void {
    const cutoff = now - this.cfg.threatWindowMs;
    let i = 0;
    while (i < this.events.length && this.events[i].ts < cutoff) i++;
    if (i > 0) this.events.splice(0, i);
  }

  private countByType(): Record<string, number> {
    const c: Record<string, number> = {};
    for (const e of this.events) c[e.type] = (c[e.type] ?? 0) + 1;
    return c;
  }

  private recomputeLevel(now: number): void {
    if (this.manualOverride) return; // sticky — D-22
    this.evict(now);
    const c = this.countByType();
    const candidates: ThreatLevel[] = ['Normal'];

    // D-19: per-type counts; level = max across types
    if ((c[POLICY_DENY] ?? 0) >= this.cfg.threatElevatedDenies)
      candidates.push('Elevated');
    if ((c[AUTH_INVALID_TOKEN] ?? 0) >= this.cfg.threatElevatedInvalidTokens)
      candidates.push('Elevated');
    if ((c[HONEYPOT_TRIGGER] ?? 0) >= this.cfg.threatElevatedHoneypot)
      candidates.push('Elevated');
    if ((c[POLICY_DENY] ?? 0) >= this.cfg.threatCriticalDenies)
      candidates.push('Critical');
    if ((c[AUTH_INVALID_TOKEN] ?? 0) >= this.cfg.threatCriticalInvalidTokens)
      candidates.push('Critical');
    if ((c[HONEYPOT_TRIGGER] ?? 0) >= this.cfg.threatCriticalHoneypot)
      candidates.push('Critical');

    const order: Record<ThreatLevel, number> = {
      Normal: 0,
      Elevated: 1,
      Critical: 2,
    };
    let next: ThreatLevel = 'Normal';
    for (const cand of candidates) if (order[cand] > order[next]) next = cand;

    if (next !== this.level) this.transitionTo(next, now);
  }

  // D-20: linear cooldown — read-time, no timers.
  private maybeCooldown(): void {
    // Cooldown gate: idle (no new signals) >= cooldownMs unlocks; stepsElapsed
    // (since last transition) determines step count. lastSignalAt resets on
    // any signal; lastTransitionAt resets on any level change.
    if (this.manualOverride) return;
    // WR-06: fast-exit when already at the floor — there is no level below
    // Normal to step down to. Avoids pointless work after long idle periods
    // and removes implicit reliance on the 'else break' branch when a future
    // ThreatLevel (e.g. 'Severe') is added above Critical.
    if (this.level === 'Normal') return;
    const now = this.clock();
    const idle = now - this.lastSignalAt;
    if (idle < this.cfg.threatCooldownMs) return;

    // Step down one level per elapsed cooldown window since last transition.
    const stepsElapsed = Math.floor(
      (now - this.lastTransitionAt) / this.cfg.threatCooldownMs,
    );
    if (stepsElapsed <= 0) return;

    let target: ThreatLevel = this.level;
    for (let i = 0; i < stepsElapsed; i++) {
      if (target === 'Critical') target = 'Elevated';
      else if (target === 'Elevated') target = 'Normal';
      else break;
    }
    if (target !== this.level) this.transitionTo(target, now);
  }

  private effectiveLevel(): ThreatLevel {
    return this.manualOverride ?? this.level;
  }

  private transitionTo(next: ThreatLevel, now: number, manual = false): void {
    const from = this.level;
    if (from === next && !manual) return;
    this.level = next;
    this.lastTransitionAt = now;

    const msg = `threat level transition ${from} → ${next}${manual ? ' (manual)' : ''}`;
    if (next === 'Critical') {
      this.logger.warn(msg);
    } else {
      this.logger.log(msg);
    }

    this.metrics.transitions.inc({
      from: from.toLowerCase(),
      to: next.toLowerCase(),
    });
    this.metrics.setThreatLevel(
      next.toLowerCase() as 'normal' | 'elevated' | 'critical',
    );
  }
}
