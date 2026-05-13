import { Module } from '@nestjs/common';
import { ConfigAppModule } from '../config/config.module';
import { TrustScoreModule } from '../trust-score/trust-score.module';
import { HASHCASH_CONFIG, type HashcashConfig } from '../config/slices';
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
      useFactory: (cfg: HashcashConfig) => new UsedNonceStore(cfg.usedNonceCapacity),
      inject: [HASHCASH_CONFIG],
    },
  ],
  exports: [HashcashService, HashcashMetrics],
})
export class HashcashModule {}
