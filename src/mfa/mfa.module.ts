import { Module } from '@nestjs/common';
import { ConfigAppModule } from '../config/config.module';
import { AuthModule } from '../auth/auth.module';
import { MfaController } from './mfa.controller';
import { MfaService } from './mfa.service';
import { MfaGuard } from './mfa.guard';
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
 * D-20: MfaGuard is NOT registered as APP_GUARD here.
 * Phase 10 will register it in the pipeline. MfaGuard is exported so Phase 10 can inject it.
 */
@Module({
  imports: [ConfigAppModule, AuthModule],
  controllers: [MfaController],
  providers: [
    MfaService,
    MfaGuard,
    MfaChallengeRepository,
    MfaTokenRepository,
    UserSecretsRepository,
    PendingEnrollmentStore,
  ],
  exports: [MfaService, MfaGuard],
})
export class MfaModule {}
