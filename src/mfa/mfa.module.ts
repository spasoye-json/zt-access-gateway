import { Module } from '@nestjs/common';
import { ConfigAppModule } from '../config/config.module';
import { AuthModule } from '../auth/auth.module';
import { SharedModule } from '../shared/shared.module';
import { MfaController } from './mfa.controller';
import { MfaChallenger } from './mfa-challenger.service';
import { MfaEnroller } from './mfa-enroller.service';
import { MfaErrorRecorder } from './mfa-error-recorder.util';
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
 * GatewayMiddleware step 9b calls MfaChallenger.validateMfaToken inline.
 *
 * Phase C (260513-mar): the previous god-class was split into MfaChallenger
 * (challenge half, consumed by GatewayMiddleware + MfaController) and
 * MfaEnroller (enrollment half, consumed only by MfaController). Both share
 * MfaErrorRecorder for the swallowed-infra-error observability path.
 */
@Module({
  imports: [ConfigAppModule, AuthModule, SharedModule],
  controllers: [MfaController],
  providers: [
    MfaChallenger,
    MfaEnroller,
    MfaErrorRecorder,
    MfaChallengeRepository,
    MfaTokenRepository,
    UserSecretsRepository,
    PendingEnrollmentStore,
  ],
  exports: [MfaChallenger, MfaEnroller],
})
export class MfaModule {}
