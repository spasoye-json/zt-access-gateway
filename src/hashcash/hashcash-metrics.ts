import { Injectable } from '@nestjs/common';
import { Counter, Histogram, Registry } from 'prom-client';

/**
 * Phase 5 — Hashcash PoW metrics (D-14, D-15, D-16).
 *
 * Owns a private `Registry` so multiple instances (production + tests) do not collide
 * on the prom-client global registry (Pitfall 3 in 05-RESEARCH.md).
 *
 * Phase 9 MetricsService can collect from `this.registry` when it merges all gateway metrics.
 */
@Injectable()
export class HashcashMetrics {
  readonly registry = new Registry();

  readonly total = new Counter({
    name: 'zt_gateway_hashcash_total',
    help: 'Hashcash PoW outcomes by result and difficulty',
    labelNames: ['outcome', 'difficulty'] as const,
    registers: [this.registry],
  });

  readonly solveSeconds = new Histogram({
    name: 'zt_gateway_hashcash_solve_seconds',
    help: 'Server-measured time from challenge issuance to solution submission',
    buckets: [0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10],
    registers: [this.registry],
  });
}
