import { Module } from '@nestjs/common';
import { ConfigAppModule } from '../config/config.module';
import { AuthModule } from '../auth/auth.module';
import { SharedModule } from '../shared/shared.module';
import { TrustScoreModule } from '../trust-score/trust-score.module';
import { HashcashModule } from '../hashcash/hashcash.module';
import { PolicyModule } from '../policy/policy.module';
import { MfaModule } from '../mfa/mfa.module';
import { ProxyModule } from '../proxy/proxy.module';
import { AuditModule } from '../audit/audit.module';
import { MetricsModule } from '../metrics/metrics.module';
import { FingerprintModule } from '../fingerprint/fingerprint.module';
import { GatewayMiddleware } from './gateway.middleware';
import { PipelineOrchestrator } from './pipeline/orchestrator';
import { PIPELINE_STAGES } from './pipeline/stage-tokens';
import type { PipelineStage } from './pipeline/pipeline-stage';
import { PublicBypassStage } from './pipeline/stages/public-bypass.stage';
import { HoneypotBypassStage } from './pipeline/stages/honeypot-bypass.stage';
import { AuthStage } from './pipeline/stages/auth.stage';
import { RevocationStage } from './pipeline/stages/revocation.stage';
import { AuthOnlyShortCircuitStage } from './pipeline/stages/auth-only-shortcircuit.stage';
import { TrustScoreStage } from './pipeline/stages/trust-score.stage';
import { HashcashStage } from './pipeline/stages/hashcash.stage';
import { PolicyStage } from './pipeline/stages/policy.stage';
import { MfaPromotionStage } from './pipeline/stages/mfa-promotion.stage';
import { AuditAllowStage } from './pipeline/stages/audit-allow.stage';
import { ProxyStage } from './pipeline/stages/proxy.stage';
import { BoplaStripStage } from './pipeline/stages/bopla-strip.stage';
import { RecordTrustContextStage } from './pipeline/stages/record-trust-context.stage';
import { StageDetailRegistry } from './pipeline/logging/stage-detail-registry';
import { StageLoggerDecorator } from './pipeline/logging/stage-logger-decorator';
import { wrapStages } from './pipeline/logging/wrap-stages';
import { registerDefaultDetailBuilders } from './pipeline/logging/default-detail-builders';

/**
 * Phase 10 / D — GatewayModule wires the 9 prerequisite modules plus the
 * 13 pipeline stages and the PipelineOrchestrator. The PIPELINE_STAGES
 * factory provider gathers the stages **in canonical execution order** —
 * adding a new stage is one new file + one entry below (no edits to the
 * middleware or the metrics union).
 *
 * Notably this module does NOT import the honeypot DI module — Pitfall 6 of
 * 10-RESEARCH.md. HoneypotBypassStage statically imports HONEYPOT_PATHS to
 * avoid the FingerprintStore DI cycle.
 */
@Module({
  imports: [
    ConfigAppModule,
    SharedModule,
    AuthModule,
    TrustScoreModule,
    HashcashModule,
    PolicyModule,
    MfaModule,
    ProxyModule,
    AuditModule,
    MetricsModule,
    FingerprintModule,
  ],
  providers: [
    GatewayMiddleware,
    PipelineOrchestrator,
    PublicBypassStage,
    HoneypotBypassStage,
    AuthStage,
    RevocationStage,
    AuthOnlyShortCircuitStage,
    TrustScoreStage,
    HashcashStage,
    PolicyStage,
    MfaPromotionStage,
    AuditAllowStage,
    ProxyStage,
    BoplaStripStage,
    RecordTrustContextStage,
    StageDetailRegistry,
    StageLoggerDecorator,
    {
      provide: PIPELINE_STAGES,
      // Factory order = execution order. Do not reorder casually.
      // Wrapping happens once at module construction so the orchestrator
      // sees the decorated PipelineStage interface and is itself untouched.
      useFactory: (
        s1: PublicBypassStage,
        s2: HoneypotBypassStage,
        s3: AuthStage,
        s4: RevocationStage,
        s5: AuthOnlyShortCircuitStage,
        s6: TrustScoreStage,
        s7: HashcashStage,
        s8: PolicyStage,
        s9: MfaPromotionStage,
        s10: AuditAllowStage,
        s11: ProxyStage,
        s12: BoplaStripStage,
        s13: RecordTrustContextStage,
        registry: StageDetailRegistry,
        decorator: StageLoggerDecorator,
      ): readonly PipelineStage[] => {
        registerDefaultDetailBuilders(registry);
        return wrapStages([s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13], decorator);
      },
      inject: [
        PublicBypassStage,
        HoneypotBypassStage,
        AuthStage,
        RevocationStage,
        AuthOnlyShortCircuitStage,
        TrustScoreStage,
        HashcashStage,
        PolicyStage,
        MfaPromotionStage,
        AuditAllowStage,
        ProxyStage,
        BoplaStripStage,
        RecordTrustContextStage,
        StageDetailRegistry,
        StageLoggerDecorator,
      ],
    },
  ],
  exports: [GatewayMiddleware, PipelineOrchestrator],
})
export class GatewayModule {}
