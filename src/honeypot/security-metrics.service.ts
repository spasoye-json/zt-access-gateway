import { Injectable } from '@nestjs/common';
import { Counter, Registry } from 'prom-client';

/**
 * SecurityMetricsService exposes honeypot-specific Prometheus metrics.
 *
 * Uses an isolated prom-client Registry (not the global singleton) to prevent
 * "metric already registered" errors when test files re-import this module in
 * separate Jest workers (documented pitfall in 02-RESEARCH.md Pitfall 2).
 * Phase 9 MetricsModule will aggregate registries if cross-module scraping is needed.
 */
@Injectable()
export class SecurityMetricsService {
  private readonly registry: Registry;
  private readonly honeypotTriggers: Counter;

  constructor() {
    this.registry = new Registry();
    this.honeypotTriggers = new Counter({
      name: 'zt_gateway_honeypot_triggers_total',
      help: 'Total number of honeypot route hits',
      registers: [this.registry],
    });
  }

  /** Increment the honeypot triggers counter by 1. */
  incrementHoneypotTriggers(): void {
    this.honeypotTriggers.inc();
  }

  /** Returns Prometheus text format metrics string for this registry. */
  async getMetrics(): Promise<string> {
    return this.registry.metrics();
  }
}
