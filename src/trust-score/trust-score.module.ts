import { Module } from '@nestjs/common';
import { TrustScoreService } from './trust-score.service';
import { TrustScoreController } from './trust-score.controller';
import { TrustTelemetryRepository } from './trust-telemetry.repository';

@Module({
  controllers: [TrustScoreController],
  providers: [TrustScoreService, TrustTelemetryRepository],
  exports: [TrustScoreService],
})
export class TrustScoreModule {}
