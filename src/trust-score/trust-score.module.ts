import { Module } from '@nestjs/common';
import { ConfigAppModule } from '../config/config.module';
import { FingerprintModule } from '../fingerprint/fingerprint.module';
import { TrustTelemetryRepository } from './trust-telemetry.repository';
import { TrustScoreService } from './trust-score.service';
import { DeviceReputationProvider } from './providers/device-reputation.provider';
import { IpReputationProvider } from './providers/ip-reputation.provider';
import { Ja4hDriftProvider } from './providers/ja4h-drift.provider';
import { RequestFrequencyProvider } from './providers/request-frequency.provider';
import { TrustDecayProvider } from './providers/trust-decay.provider';
import { BehaviorAnomalyProvider } from './providers/behavior-anomaly.provider';

@Module({
  imports: [ConfigAppModule, FingerprintModule],
  providers: [
    TrustTelemetryRepository,
    DeviceReputationProvider,
    IpReputationProvider,
    Ja4hDriftProvider,
    RequestFrequencyProvider,
    TrustDecayProvider,
    BehaviorAnomalyProvider,
    TrustScoreService,
  ],
  exports: [TrustScoreService, TrustTelemetryRepository],
})
export class TrustScoreModule {}
