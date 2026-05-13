import { Module } from '@nestjs/common';
import { ConfigAppModule } from '../config/config.module';
import { CertMonitorService } from './cert-monitor.service';
import { HealthController } from './health.controller';
import { MtlsService } from './mtls.service';
import { TypedEvents } from './typed-events';

/**
 * SharedModule provides cross-cutting infrastructure consumed by the full pipeline.
 * Imports ConfigAppModule explicitly so AppConfigService is resolvable via DI
 * in both production and TestingModule contexts (isGlobal only covers @nestjs/config
 * ConfigService, not the AppConfigService wrapper).
 *
 * Exports MtlsService (ProxyService consumer) and TypedEvents (every emit site
 * across mfa/policy/audit/auth/honeypot/fingerprint/trust-score/gateway).
 * EventEmitter2 itself is provided globally by EventEmitterModule.forRoot()
 * at app.module.ts, so no event-emitter import is needed here.
 * CertMonitorService is internal: it only calls mtlsService.reload() on file changes.
 */
@Module({
  imports: [ConfigAppModule],
  providers: [MtlsService, CertMonitorService, TypedEvents],
  controllers: [HealthController],
  exports: [MtlsService, TypedEvents],
})
export class SharedModule {}
