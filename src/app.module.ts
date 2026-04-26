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

/**
 * AppModule — root module wiring the full Phase 2-6 pipeline.
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
 *
 * EventEmitterModule (Phase 6 D-13) is registered globally immediately after
 * ConfigAppModule so all subsequent modules see EventEmitter2 globally.
 *
 * HoneypotModule imported last to prevent shadow controller routes from
 * matching before any real routes (T-02-11, Pitfall 3 in 02-RESEARCH.md).
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
    HoneypotModule, // Pitfall 3: stays last (Phase 2)
  ],
  controllers: [],
  providers: [],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // Apply JA4H fingerprinting to all routes — runs after global Express
    // middleware (Helmet, CORS, rate-limit) but before NestJS guards (auth).
    consumer.apply(Ja4hMiddleware).forRoutes('*');
  }
}
