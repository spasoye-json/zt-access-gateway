import { Module } from '@nestjs/common';
import { ConfigAppModule } from '../config/config.module';
import { SharedModule } from '../shared/shared.module';
import { BoPlaInterceptor } from './bopla.interceptor';
import { DnsRebindingGuard } from './dns-rebinding.guard';
import { ProxyService } from './proxy.service';
import { ServiceRegistryService } from './service-registry.service';

/**
 * Phase 8 — Proxy + BOPLA module.
 *
 * ProxyService composes ServiceRegistryService (SSRF allowlist) + DnsRebindingGuard
 * (per-request DNS resolve) + opossum (per-service circuit breakers) + axios + MtlsService
 * (Phase 1) into the full forward path. BoPlaInterceptor strips role-unauthorized fields
 * from downstream JSON responses before they leave the gateway.
 *
 * ProxyModule is imported by AppModule between MfaModule and HoneypotModule. Phase 10
 * GatewayMiddleware will inject ProxyService + BoPlaInterceptor to wire them into the
 * 10-step pipeline.
 */
@Module({
  imports: [ConfigAppModule, SharedModule], // SharedModule provides MtlsService
  providers: [
    ProxyService,
    ServiceRegistryService,
    DnsRebindingGuard,
    BoPlaInterceptor,
  ],
  exports: [ProxyService, BoPlaInterceptor],
})
export class ProxyModule {}
