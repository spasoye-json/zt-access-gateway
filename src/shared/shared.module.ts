import { Module } from '@nestjs/common';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { ConfigAppModule } from '../config/config.module';
import { CertMonitorService } from './cert-monitor.service';
import { HealthController } from './health.controller';
import { MtlsService } from './mtls.service';
import { TypedEvents } from './typed-events';

/**
 * SharedModule provides cross-cutting infrastructure consumed by the full pipeline.
 * Imports ConfigAppModule explicitly so MTLS_CONFIG (and the other domain slice
 * tokens) are resolvable via DI in both production and TestingModule contexts
 * (isGlobal only covers @nestjs/config ConfigService, not the slice useFactory
 * providers registered in ConfigAppModule).
 *
 * Exports MtlsService (ProxyService consumer) and TypedEvents (every emit site
 * across mfa/policy/audit/auth/honeypot/fingerprint/trust-score/gateway).
 * EventEmitter2 itself is provided globally by EventEmitterModule.forRoot()
 * at app.module.ts, so no event-emitter import is needed here.
 * CertMonitorService is internal: it only calls mtlsService.reload() on file changes.
 */
@Module({
  // EventEmitterModule.forRoot() is registered here so SharedModule is
  // self-contained: any test that imports a downstream module which itself
  // imports SharedModule (e.g. ProxyModule) gets EventEmitter2 resolved via DI
  // without requiring the caller to re-register the bus. AppModule registers
  // forRoot() at the root too; both registrations target the same global bus.
  imports: [ConfigAppModule, EventEmitterModule.forRoot()],
  providers: [MtlsService, CertMonitorService, TypedEvents],
  controllers: [HealthController],
  exports: [MtlsService, TypedEvents],
})
export class SharedModule {}
