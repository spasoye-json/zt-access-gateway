import { Injectable } from '@nestjs/common';
import { Counter, Gauge, Registry } from 'prom-client';

/**
 * Phase 6 — Policy + Threat Prometheus metrics (D-22 metrics suggestions).
 *
 * Owns a PRIVATE prom-client Registry to avoid the "metric already registered"
 * collision in Jest (Pitfall 6 — mirrors Phase 5 HashcashMetrics + Phase 2
 * SecurityMetricsService precedent). Phase 9 MetricsService can merge registries
 * if cross-module scraping is wired later.
 */
@Injectable()
export class PolicyMetrics {
  readonly registry = new Registry();

  readonly decisions = new Counter({
    name: 'zt_gateway_policy_decisions_total',
    help: 'Policy outcomes by decision label',
    labelNames: ['decision'] as const, // values: allow | challenge | deny
    registers: [this.registry],
  });

  readonly errors = new Counter({
    name: 'zt_gateway_policy_errors_total',
    help: 'Casbin enforcer errors (treated as DENY per D-03)',
    registers: [this.registry],
  });

  readonly threatLevel = new Gauge({
    name: 'zt_gateway_threat_level',
    help: 'Current threat level (1 = active, 0 = inactive)',
    labelNames: ['level'] as const, // values: normal | elevated | critical
    registers: [this.registry],
  });

  readonly transitions = new Counter({
    name: 'zt_gateway_threat_transitions_total',
    help: 'Threat level transitions',
    labelNames: ['from', 'to'] as const,
    registers: [this.registry],
  });

  /**
   * Helper: set the gauge so exactly one level is `1` and the other two are `0`.
   * Call from ThreatEscalationService.transitionTo().
   */
  setThreatLevel(level: 'normal' | 'elevated' | 'critical'): void {
    this.threatLevel.set({ level: 'normal' }, level === 'normal' ? 1 : 0);
    this.threatLevel.set({ level: 'elevated' }, level === 'elevated' ? 1 : 0);
    this.threatLevel.set({ level: 'critical' }, level === 'critical' ? 1 : 0);
  }
}
