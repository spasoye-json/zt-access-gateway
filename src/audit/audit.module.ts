import { Module } from '@nestjs/common';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { ConfigAppModule } from '../config/config.module';
import { AuthModule } from '../auth/auth.module';
import { SharedModule } from '../shared/shared.module';
import { AuditController } from './audit.controller';
import { AuditService } from './audit.service';
import { AuditRepository } from './audit.repository';

/**
 * Phase 9 — AuditModule (AUDT-01..06).
 *
 * Exports AuditService so Phase 10 GatewayMiddleware can inject it. Does NOT
 * import MetricsModule (D-03 — circular dep prevention). For the record() best-effort
 * path, AuditService emits `audit.record_failed` via EventEmitter2; MetricsService
 * subscribes via @OnEvent. EventEmitterModule.forRoot() is also wired in AppModule
 * (Phase 6 D-13); declaring it here is idempotent and makes the local dependency explicit.
 */
@Module({
  imports: [ConfigAppModule, AuthModule, EventEmitterModule.forRoot(), SharedModule],
  controllers: [AuditController],
  providers: [AuditService, AuditRepository],
  exports: [AuditService],
})
export class AuditModule {}
