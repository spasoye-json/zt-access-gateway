import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { ConfigAppModule } from './config/config.module';
import { AuthModule } from './auth/auth.module';
import { SharedModule } from './shared/shared.module';
import { FingerprintModule } from './fingerprint/fingerprint.module';
import { HoneypotModule } from './honeypot/honeypot.module';
import { Ja4hMiddleware } from './fingerprint/ja4h.middleware';
import { TrustScoreModule } from './trust-score/trust-score.module';
import { HashcashModule } from './hashcash/hashcash.module';
import { PolicyModule } from './policy/policy.module';
import { MfaModule } from './mfa/mfa.module';
import { ProxyModule } from './proxy/proxy.module';
import { MetricsModule } from './metrics/metrics.module';
import { AuditModule } from './audit/audit.module';
import { GatewayModule } from './gateway/gateway.module';
import { GatewayMiddleware } from './gateway/gateway.middleware';

/**
 * AppModule — root module wiring the full Phase 2-9 pipeline.
 *
 * Middleware ordering (D-04):
 *   1. Helmet (main.ts — global Express middleware, fires first)
 *   2. CORS (main.ts)
 *   3. Rate limiting (main.ts)
 *   4. JA4H fingerprinting (MiddlewareConsumer — NestJS DI-aware middleware)
 *   5. Auth guard (Phase 3 — guard-per-route, not middleware)
 *   5b. Hashcash PoW guard (Phase 5 — APP_GUARD in HashcashModule, runs after JwtAuthGuard)
 *   6. Policy + Threat Escalation guard (Phase 6 — invoked by Phase 10 GatewayMiddleware,
 *      NOT a global guard yet; PolicyEvaluatorService is exported for that consumer)
 *   7. MFA challenge endpoints (Phase 7 — MfaController + MfaService; MfaGuard exported
 *      but NOT APP_GUARD per D-20; Phase 10 registers it in the full pipeline)
 *   8. ProxyModule — mTLS forwarding + BOPLA stripping (D-01..D-12); ProxyService +
 *      BoPlaInterceptor exported for Phase 10 GatewayMiddleware injection
 *   9. MetricsModule + AuditModule — Phase 9 (D-01..D-10);
 *      MetricsModule comes AFTER HashcashModule/PolicyModule/HoneypotModule peers exist
 *      via the DI graph (Pitfall 7) but BEFORE HoneypotModule's controller registration
 *      (Pitfall 3 — Honeypot stays last). MetricsService.getAggregatedMetrics() merges
 *      all 4 registries on every /metrics scrape; AuditService is exported for Phase 10
 *      GatewayMiddleware (audit-before-allow + best-effort record).
 *
 * EventEmitterModule (Phase 6 D-13) is registered globally immediately after
 * ConfigAppModule so all subsequent modules see EventEmitter2 globally.
 *
 * HoneypotModule imported last to prevent shadow controller routes from
 * matching before any real routes (T-02-11, Pitfall 3 in 02-RESEARCH.md).
 *
 * Phase 10 (D-01..D-16): Wave 3 wired GatewayMiddleware after Ja4hMiddleware
 * (D-01) and removed APP_GUARD registrations of JwtAuthGuard / HashcashGuard
 * (D-02). Auth-only endpoints (/auth/revoke, /mfa/*) now use route-level
 * @UseGuards(JwtAuthGuard) instead. GatewayModule is imported BEFORE
 * HoneypotModule (Pitfall 6 — closes the FingerprintStore DI cycle).
 */
@Module({
  imports: [
    ConfigAppModule,
    EventEmitterModule.forRoot(), // Phase 6 — global signal bus (D-13)
    AuthModule,
    SharedModule,
    FingerprintModule,
    TrustScoreModule,
    HashcashModule,
    PolicyModule, // Phase 6 — D-24 module structure (after Hashcash, before Honeypot)
    MfaModule, // Phase 7 — D-19 (after PolicyModule, before HoneypotModule)
    ProxyModule, // Phase 8 — D-01..D-12 (wave 3; before HoneypotModule)
    MetricsModule, // Phase 9 — registry merge (after Hashcash/Policy peers, before Honeypot last)
    AuditModule, // Phase 9 — WAL writer + admin query endpoint
    GatewayModule, // Phase 10 — orchestrator wiring (D-01); MUST be before HoneypotModule (Pitfall 6)
    HoneypotModule, // Pitfall 3: stays last (Phase 2)
  ],
  controllers: [],
  providers: [],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // D-01: Ja4hMiddleware FIRST (it stamps req['x-ja4h']),
    //       GatewayMiddleware SECOND (orchestrates 10-step pipeline).
    consumer.apply(Ja4hMiddleware).forRoutes('*');
    consumer.apply(GatewayMiddleware).forRoutes('*');
  }
}
