import { Controller, Get, Res } from '@nestjs/common';
import type { Response } from 'express';
import { Registry } from 'prom-client';
import { Public } from '../shared/public.decorator';
import { MetricsService } from './metrics.service';

/**
 * Phase 9 — Prometheus scrape endpoint (MTRC-03).
 *
 * @Public() applied at class level so JwtAuthGuard skips authentication
 * (mirrors HealthController). Returns Prometheus exposition format with
 * Content-Type per Registry.PROMETHEUS_CONTENT_TYPE (text/plain; version=0.0.4; charset=utf-8)
 * — bypasses NestJS JSON via @Res().
 */
@Public()
@Controller('metrics')
export class MetricsController {
  constructor(private readonly metricsService: MetricsService) {}

  @Get()
  async getMetrics(@Res() res: Response): Promise<void> {
    const body = await this.metricsService.getAggregatedMetrics();
    res
      .set('Content-Type', Registry.PROMETHEUS_CONTENT_TYPE)
      .status(200)
      .send(body);
  }
}
