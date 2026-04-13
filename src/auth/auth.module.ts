import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ConfigAppModule } from '../config/config.module';
import { AuthService } from './auth.service';
import { TokenRevocationService } from './token-revocation.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RolesGuard } from './roles.guard';

/**
 * AuthModule -- JWT authentication and RBAC authorization.
 * Registers JwtAuthGuard and RolesGuard as global APP_GUARDs.
 * Guard ordering: JwtAuthGuard BEFORE RolesGuard (Pitfall 3 -- NestJS
 * executes APP_GUARD providers in declaration order).
 */
@Module({
  imports: [ConfigAppModule],
  providers: [
    AuthService,
    TokenRevocationService,
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
  ],
  controllers: [], // AuthController added in Plan 03-03
  exports: [AuthService, TokenRevocationService],
})
export class AuthModule {}
