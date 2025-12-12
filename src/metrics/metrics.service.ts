import { Injectable, Logger } from '@nestjs/common';
import {
  Counter,
  Histogram,
  Registry,
  collectDefaultMetrics,
} from 'prom-client';

export interface RequestMetrics {
  requestId: string;
  evaluationLatencyMs: number;
  requestForwardLatencyMs: number;
  totalGatewayLatencyMs: number;
  decision: 'ALLOW' | 'DENY' | 'CHALLENGE';
  trustScore: number;
}

@Injectable()
export class MetricsService {
  private readonly logger = new Logger(MetricsService.name);
  private readonly registry = new Registry();
  private readonly requestCounter: Counter<string>;
  private readonly trustLevelCounter: Counter<string>;
  private readonly trustScoreHistogram: Histogram<string>;
  private readonly evaluationLatencyHistogram: Histogram<string>;
  private readonly forwardLatencyHistogram: Histogram<string>;
  private readonly totalLatencyHistogram: Histogram<string>;

  constructor() {
    collectDefaultMetrics({
      register: this.registry,
      prefix: 'zt_gateway_',
    });

    this.requestCounter = new Counter({
      name: 'zt_gateway_requests_total',
      help: 'Total gateway requests partitioned by decision',
      labelNames: ['decision'],
      registers: [this.registry],
    });

    this.trustLevelCounter = new Counter({
      name: 'zt_gateway_trust_level_total',
      help: 'Count of trust score levels observed',
      labelNames: ['level'],
      registers: [this.registry],
    });

    this.trustScoreHistogram = new Histogram({
      name: 'zt_gateway_trust_score',
      help: 'Distribution of trust scores',
      buckets: [0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 1],
      registers: [this.registry],
    });

    this.evaluationLatencyHistogram = new Histogram({
      name: 'zt_gateway_evaluation_latency_ms',
      help: 'Latency for authentication/trust/policy evaluation',
      buckets: [1, 5, 10, 25, 50, 100, 250, 500],
      registers: [this.registry],
    });

    this.forwardLatencyHistogram = new Histogram({
      name: 'zt_gateway_forward_latency_ms',
      help: 'Latency for proxy forwarding to downstream services',
      buckets: [1, 5, 10, 25, 50, 100, 250, 500, 1000],
      registers: [this.registry],
    });

    this.totalLatencyHistogram = new Histogram({
      name: 'zt_gateway_total_latency_ms',
      help: 'End-to-end latency through the gateway',
      buckets: [5, 10, 25, 50, 100, 250, 500, 1000, 2000],
      registers: [this.registry],
    });
  }

  async recordRequestMetrics(metrics: RequestMetrics): Promise<void> {
    try {
      this.requestCounter.labels(metrics.decision).inc();
      this.evaluationLatencyHistogram.observe(metrics.evaluationLatencyMs);
      this.forwardLatencyHistogram.observe(metrics.requestForwardLatencyMs);
      this.totalLatencyHistogram.observe(metrics.totalGatewayLatencyMs);
      this.trustScoreHistogram.observe(metrics.trustScore);

      let level: string;
      if (metrics.trustScore < 0.3) {
        level = 'low';
      } else if (metrics.trustScore < 0.7) {
        level = 'medium';
      } else {
        level = 'high';
      }
      this.trustLevelCounter.labels(level).inc();

      this.logger.debug(`Recorded metrics for request ${metrics.requestId}`);
    } catch (error) {
      this.logger.warn(`Failed to record metrics for ${metrics.requestId}: ${error.message}`);
    }
  }

  async getMetrics(): Promise<string> {
    return this.registry.metrics();
  }

  getContentType(): string {
    return this.registry.contentType;
  }

  resetMetrics(): void {
    this.registry.resetMetrics();
  }
}
