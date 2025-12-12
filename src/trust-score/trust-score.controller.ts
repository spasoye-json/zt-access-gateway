import { Controller, Get, Query } from '@nestjs/common';
import { TrustScoreService } from './trust-score.service';
import { TrustScoreResult } from './trust-score.service';

@Controller('trust-score')
export class TrustScoreController {
  constructor(private readonly trustScoreService: TrustScoreService) {}

  @Get('calculate')
  async calculateTrustScore(
    @Query('userId') userId: string,
    @Query('deviceId') deviceId: string,
    @Query('ip') ip: string,
  ): Promise<TrustScoreResult> {
    return this.trustScoreService.calculateTrustScore(userId, deviceId, ip);
  }
}