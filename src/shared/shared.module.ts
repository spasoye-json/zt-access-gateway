import { Module } from '@nestjs/common';
import { CertMonitorService } from './cert-monitor.service';
import { HealthController } from './health.controller';
import { MtlsService } from './mtls.service';

/**
 * SharedModule provides cross-cutting infrastructure consumed by the full pipeline.
 * ConfigAppModule is global (isGlobal: true) so AppConfigService is injected
 * without importing ConfigAppModule here.
 *
 * Exports only MtlsService — ProxyService (Phase 8) is the primary consumer.
 * CertMonitorService is internal: it only calls mtlsService.reload() on file changes.
 */
@Module({
  providers: [MtlsService, CertMonitorService],
  controllers: [HealthController],
  exports: [MtlsService],
})
export class SharedModule {}
