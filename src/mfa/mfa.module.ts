import { Module } from '@nestjs/common';
import { ConfigAppModule } from '../config/config.module';
import { AuthModule } from '../auth/auth.module';
import { MfaController } from './mfa.controller';
import { MfaService } from './mfa.service';
import { MfaChallengeRepository } from './repositories/mfa-challenge.repository';
import { MfaTokenRepository } from './repositories/mfa-token.repository';
import { UserSecretsRepository } from './repositories/user-secrets.repository';
import { PendingEnrollmentStore } from './enrollment.store';

/**
 * Phase 7 — MfaModule (D-19).
 *
 * Imports: ConfigAppModule (env), AuthModule (JwtAuthGuard + UserClaims contract).
 * EventEmitterModule is global (AppModule root, Phase 6 D-13) — no re-import needed.
 *
 * Phase 14 (Item 12): orphan guard export removed — it had no live consumer.
 * GatewayMiddleware step 9b calls MfaService.validateMfaToken inline.
 */
@Module({
  imports: [ConfigAppModule, AuthModule],
  controllers: [MfaController],
  providers: [
    MfaService,
    MfaChallengeRepository,
    MfaTokenRepository,
    UserSecretsRepository,
    PendingEnrollmentStore,
  ],
  exports: [MfaService],
})
export class MfaModule {}
