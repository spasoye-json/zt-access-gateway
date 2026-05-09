import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { ConfigAppModule } from '../config/config.module';
import { AuthService } from './auth.service';
import { TokenRevocationService } from './token-revocation.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RolesGuard } from './roles.guard';
import { AuthController } from './auth.controller';

/**
 * AuthModule -- JWT authentication and RBAC authorization.
 *
 * Phase 10 (D-02): JwtAuthGuard is no longer registered as APP_GUARD --
 * GatewayMiddleware calls AuthService.validateToken() inline for all proxied
 * routes. JwtAuthGuard remains a class-level injectable for route-level
 * @UseGuards on auth-only endpoints (/auth/revoke, /mfa/*).
 * RolesGuard stays as APP_GUARD -- it reads req.user set by GatewayMiddleware
 * and continues to enforce @Roles('admin') on policy/audit admin routes.
 *
 * Phase 6: imports EventEmitterModule so JwtAuthGuard can inject EventEmitter2
 * for AUTH_INVALID_TOKEN signal emission. Idempotent with the global root
 * registration that lands in AppModule (Plan 06).
 */
@Module({
  imports: [ConfigAppModule, EventEmitterModule.forRoot()],
  providers: [
    AuthService,
    TokenRevocationService,
    JwtAuthGuard,
    { provide: APP_GUARD, useClass: RolesGuard },
  ],
  controllers: [AuthController],
  exports: [AuthService, TokenRevocationService, JwtAuthGuard],
})
export class AuthModule {}
