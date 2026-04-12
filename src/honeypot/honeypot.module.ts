import { Module } from '@nestjs/common';
import { FingerprintModule } from '../fingerprint/fingerprint.module';
import { ConfigAppModule } from '../config/config.module';
import { ShadowController } from './shadow.controller';
import { SecurityMetricsService } from './security-metrics.service';

/**
 * HoneypotModule — deception layer that traps and blacklists scanners.
 *
 * Imported last in AppModule to prevent shadow controller routes from
 * matching before any real routes are registered (T-02-11, Pitfall 3).
 */
@Module({
  imports: [FingerprintModule, ConfigAppModule],
  controllers: [ShadowController],
  providers: [SecurityMetricsService],
  exports: [SecurityMetricsService],
})
export class HoneypotModule {}
