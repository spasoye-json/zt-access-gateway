import { Module } from '@nestjs/common';
import { ConfigAppModule } from '../config/config.module';
import { AuthModule } from '../auth/auth.module';
import { TrustScoreModule } from '../trust-score/trust-score.module';
import { HashcashModule } from '../hashcash/hashcash.module';
import { PolicyModule } from '../policy/policy.module';
import { MfaModule } from '../mfa/mfa.module';
import { ProxyModule } from '../proxy/proxy.module';
import { AuditModule } from '../audit/audit.module';
import { MetricsModule } from '../metrics/metrics.module';
import { FingerprintModule } from '../fingerprint/fingerprint.module';
import { GatewayMiddleware } from './gateway.middleware';

/**
 * Phase 10 — GatewayModule wires the 9 prerequisite modules so that
 * GatewayMiddleware can inject every service it orchestrates.
 *
 * EventEmitter2 is provided by EventEmitterModule.forRoot() at the
 * AppModule level (verified) — no need to import it here. If a future
 * change moves it, add `EventEmitterModule.forRoot()` to this module's
 * imports so D-10 AUDIT_SIGNAL emission resolves.
 *
 * Notably this module does NOT import the honeypot DI module — Pitfall 6 of
 * 10-RESEARCH.md. The honeypot path bypass uses a static import of
 * src/honeypot/honeypot.constants.ts (a plain TypeScript export), avoiding
 * the circular DI cycle that the honeypot module -> ShadowController chain
 * would create through FingerprintStore.
 */
@Module({
  imports: [
    ConfigAppModule,
    AuthModule,
    TrustScoreModule,
    HashcashModule,
    PolicyModule,
    MfaModule,
    ProxyModule, // exports ProxyService + BoPlaInterceptor
    AuditModule,
    MetricsModule,
    FingerprintModule,
  ],
  providers: [GatewayMiddleware],
  exports: [GatewayMiddleware],
})
export class GatewayModule {}
