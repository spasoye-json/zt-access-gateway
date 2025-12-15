import { Controller, Get, Headers, Request, UnauthorizedException } from '@nestjs/common';
import type { Request as ExpressRequest } from 'express';
import { TrustScoreService, TrustScoreResult } from './trust-score.service';
import { UserClaims } from '../auth/auth.service';
import {
  extractClientIp,
  resolveDeviceId,
} from '../shared/request-context.util';

@Controller('trust-score')
export class TrustScoreController {
  constructor(private readonly trustScoreService: TrustScoreService) {}

  @Get('calculate')
  async calculateTrustScore(
    @Request() req: ExpressRequest & { userClaims?: UserClaims },
    @Headers('x-device-id') deviceId?: string,
    @Headers('user-agent') userAgent?: string,
  ): Promise<TrustScoreResult> {
    if (!req.userClaims) {
      throw new UnauthorizedException('Missing authenticated user');
    }

    const ip = extractClientIp(req);
    const normalizedDeviceId = resolveDeviceId(deviceId);
    const normalizedUserAgent =
      typeof userAgent === 'string' && userAgent.length > 0
        ? userAgent
        : 'unknown';

    return this.trustScoreService.calculateTrustScore(
      req.userClaims.userId,
      normalizedDeviceId,
      ip,
      normalizedUserAgent,
    );
  }
}
