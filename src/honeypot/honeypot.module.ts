import { Module } from '@nestjs/common';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { FingerprintModule } from '../fingerprint/fingerprint.module';
import { ConfigAppModule } from '../config/config.module';
import { SharedModule } from '../shared/shared.module';
import { ShadowController } from './shadow.controller';
import { SecurityMetricsService } from './security-metrics.service';

/**
 * HoneypotModule — deception layer that traps and blacklists scanners.
 *
 * Imported last in AppModule to prevent shadow controller routes from
 * matching before any real routes are registered (T-02-11, Pitfall 3).
 *
 * Phase 6: imports EventEmitterModule so ShadowController can inject
 * EventEmitter2 for HONEYPOT_TRIGGER signal emission. Idempotent with
 * the global root that lands in AppModule (Plan 06).
 */
@Module({
  imports: [FingerprintModule, ConfigAppModule, EventEmitterModule.forRoot(), SharedModule],
  controllers: [ShadowController],
  providers: [SecurityMetricsService],
  exports: [SecurityMetricsService],
})
export class HoneypotModule {}
