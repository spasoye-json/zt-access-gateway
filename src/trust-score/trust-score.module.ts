import { Module } from '@nestjs/common';
import { ConfigAppModule } from '../config/config.module';
import { FingerprintModule } from '../fingerprint/fingerprint.module';
import { SharedModule } from '../shared/shared.module';
import { TrustTelemetryRepository } from './trust-telemetry.repository';
import { TrustScoreService } from './trust-score.service';
import { Ja4hDriftProvider } from './providers/ja4h-drift.provider';
import { TrustDecayProvider } from './providers/trust-decay.provider';
import { BehaviorAnomalyProvider } from './providers/behavior-anomaly.provider';
import { SIGNAL_RULES_TOKEN } from './signal-rules.token';
import { SIGNAL_RULES } from './signal-rules';

@Module({
  imports: [ConfigAppModule, FingerprintModule, SharedModule],
  providers: [
    TrustTelemetryRepository,
    Ja4hDriftProvider,
    TrustDecayProvider,
    BehaviorAnomalyProvider,
    { provide: SIGNAL_RULES_TOKEN, useValue: SIGNAL_RULES },
    TrustScoreService,
  ],
  exports: [TrustScoreService, TrustTelemetryRepository],
})
export class TrustScoreModule {}
