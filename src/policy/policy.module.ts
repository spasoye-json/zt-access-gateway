import { Module } from '@nestjs/common';
import { ConfigAppModule } from '../config/config.module';
import { AuthModule } from '../auth/auth.module';
import { SharedModule } from '../shared/shared.module';
import { TrustScoreModule } from '../trust-score/trust-score.module';
import { PolicyEvaluatorService } from './policy-evaluator.service';
import { ThreatEscalationService } from './threat-escalation.service';
import { PolicyAdminController } from './policy-admin.controller';
import { PolicyMetrics } from './policy-metrics';

/**
 * Phase 6 — Policy + Threat Escalation module (D-24).
 *
 * Provides:
 *   - PolicyEvaluatorService — Casbin enforcer + fail-closed evaluate() + writer-mutex mutators
 *   - ThreatEscalationService — sliding-window aggregator + threshold getters
 *   - PolicyAdminController — admin REST API (rules CRUD + escalation override)
 *   - PolicyMetrics — prom-client metrics on a private Registry
 *
 * Import ordering (D-06 / Pitfall 2): PolicyModule must be imported AFTER AuthModule
 * (so JwtAuthGuard runs first to populate request.user) and AFTER HashcashModule
 * (PoW gates high-risk requests in step 7 before policy in step 8).
 *
 * IMPORTANT (D-12): HASHCASH_TRIGGER_THRESHOLD (Phase 5, step 7) is INDEPENDENT of
 * POLICY_CHALLENGE_THRESHOLD / POLICY_DENY_THRESHOLD (this module, step 8). Both are
 * applied per HARDENING_ARCHITECTURE.md fail-fast pipeline.
 *
 * The signal bus (@nestjs/event-emitter) is registered globally in AppModule via
 * EventEmitterModule.forRoot(); ThreatEscalationService subscribes to all 5 event
 * names from day one (3 active emitters in Phase 6, 2 silent for Phase 7/9).
 *
 * PolicyMetrics is exported so Phase 9 MetricsService can later merge registries
 * (deferred — leaves the seam).
 */
@Module({
  imports: [ConfigAppModule, AuthModule, TrustScoreModule, SharedModule],
  controllers: [PolicyAdminController],
  providers: [PolicyEvaluatorService, ThreatEscalationService, PolicyMetrics],
  exports: [PolicyEvaluatorService, ThreatEscalationService, PolicyMetrics],
})
export class PolicyModule {}
