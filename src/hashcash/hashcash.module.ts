import { Module } from '@nestjs/common';
import { ConfigAppModule } from '../config/config.module';
import { TrustScoreModule } from '../trust-score/trust-score.module';
import { AppConfigService } from '../config/config.service';
import { HashcashService } from './hashcash.service';
import { HashcashMetrics } from './hashcash-metrics';
import { UsedNonceStore } from './used-nonce-store';

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
