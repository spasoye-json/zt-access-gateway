import { Module } from '@nestjs/common';
import { ConfigAppModule } from '../config/config.module';
import { TrustScoreModule } from '../trust-score/trust-score.module';
import { AppConfigService } from '../config/config.service';
import { HashcashService } from './hashcash.service';
import { HashcashMetrics } from './hashcash-metrics';
import { UsedNonceStore } from './used-nonce-store';

/**
 * Phase 10 (D-02): HashcashGuard is no longer registered as APP_GUARD --
 * GatewayMiddleware calls HashcashService.verifySolution() / issueChallenge()
 * inline as pipeline step 8. The guard class remains in src/hashcash/ for
 * historical reference / future @UseGuards consumers.
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
  ],
  exports: [HashcashService, HashcashMetrics],
})
export class HashcashModule {}
