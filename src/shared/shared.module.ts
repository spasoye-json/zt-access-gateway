import { Module } from '@nestjs/common';
import { ConfigAppModule } from '../config/config.module';
import { CertMonitorService } from './cert-monitor.service';
import { HealthController } from './health.controller';
import { MtlsService } from './mtls.service';

/**
 * SharedModule provides cross-cutting infrastructure consumed by the full pipeline.
 * Imports ConfigAppModule explicitly so AppConfigService is resolvable via DI
 * in both production and TestingModule contexts (isGlobal only covers @nestjs/config
 * ConfigService, not the AppConfigService wrapper).
 *
 * Exports only MtlsService — ProxyService (Phase 8) is the primary consumer.
 * CertMonitorService is internal: it only calls mtlsService.reload() on file changes.
 */
@Module({
  imports: [ConfigAppModule],
  providers: [MtlsService, CertMonitorService],
  controllers: [HealthController],
  exports: [MtlsService],
})
export class SharedModule {}
