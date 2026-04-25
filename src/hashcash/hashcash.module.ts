import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ConfigAppModule } from '../config/config.module';
import { TrustScoreModule } from '../trust-score/trust-score.module';
import { AppConfigService } from '../config/config.service';
import { HashcashService } from './hashcash.service';
import { HashcashGuard } from './hashcash.guard';
import { HashcashMetrics } from './hashcash-metrics';
import { UsedNonceStore } from './used-nonce-store';

/**
 * Phase 5 — Hashcash PoW module (D-06, D-18).
 *
 * IMPORTANT (Pitfall 2): AppModule MUST import AuthModule BEFORE HashcashModule.
 * NestJS executes APP_GUARD providers in module-import order, so JwtAuthGuard
 * must run first to populate request.user before HashcashGuard reads it.
 */
@Module({
  imports: [ConfigAppModule, TrustScoreModule],
  providers: [
    HashcashService,
    HashcashMetrics,
    {
      provide: UsedNonceStore,
      useFactory: (cfg: AppConfigService) => new UsedNonceStore(cfg.hashcashUsedNonceCapacity),
      inject: [AppConfigService],
    },
    { provide: APP_GUARD, useClass: HashcashGuard },
  ],
  exports: [HashcashService],
})
export class HashcashModule {}
