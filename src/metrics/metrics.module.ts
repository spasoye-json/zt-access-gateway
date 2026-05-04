import { Module } from '@nestjs/common';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { ConfigAppModule } from '../config/config.module';
import { HoneypotModule } from '../honeypot/honeypot.module';
import { HashcashModule } from '../hashcash/hashcash.module';
import { PolicyModule } from '../policy/policy.module';
import { MetricsService } from './metrics.service';
import { MetricsController } from './metrics.controller';

/**
 * Phase 9 — MetricsModule (MTRC-01..05, D-01..D-03).
 *
 * Imports the three modules whose injectable metric services must be merged
 * into the /metrics scrape:
 *   - HoneypotModule  → SecurityMetricsService.getRegistry()
 *   - HashcashModule  → HashcashMetrics.registry (Gap 2 closed in Plan 09-00)
 *   - PolicyModule    → PolicyMetrics.registry
 *
 * Exports MetricsService so Phase 10 GatewayMiddleware can call seam methods
 * (incrementRequest, observeStageDuration, observeAuditWalDuration, etc.).
 *
 * Import-order rule (Pitfall 7, enforced in AppModule by Plan 09-03):
 * MetricsModule must come AFTER HoneypotModule/HashcashModule/PolicyModule
 * but BEFORE the final HoneypotModule reorder — Plan 09-03 wires the final order.
 */
@Module({
  imports: [ConfigAppModule, HoneypotModule, HashcashModule, PolicyModule, EventEmitterModule.forRoot()],
  controllers: [MetricsController],
  providers: [MetricsService],
  exports: [MetricsService],
})
export class MetricsModule {}
