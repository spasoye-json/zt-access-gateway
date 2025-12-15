import {
  BadRequestException,
  Controller,
  Get,
  Headers,
  Query,
  Request,
} from '@nestjs/common';
import type { Request as ExpressRequest } from 'express';
import { PolicyService } from './policy.service';
import { PolicyDecision } from './policy-evaluator.service';
import { Roles } from '../auth/roles.decorator';
import { UserClaims } from '../auth/auth.service';
import { TrustScoreService } from '../trust-score/trust-score.service';
import {
  extractClientIp,
  resolveDeviceId,
} from '../shared/request-context.util';

@Roles('admin')
@Controller('policy')
export class PolicyController {
  constructor(
    private readonly policyService: PolicyService,
    private readonly trustScoreService: TrustScoreService,
  ) {}

  @Get('evaluate')
  async evaluatePolicy(
    @Query('resource') resource: string,
    @Query('action') action: string,
    @Request() req: ExpressRequest & { userClaims?: UserClaims },
    @Headers('x-device-id') deviceId?: string,
    @Headers('user-agent') userAgent?: string,
  ): Promise<PolicyDecision> {
    if (!resource || !action) {
      throw new BadRequestException('resource and action are required');
    }

    if (!req.userClaims) {
      throw new BadRequestException('User context missing');
    }

    const ip = extractClientIp(req);
    const normalizedDeviceId = resolveDeviceId(deviceId);
    const normalizedUserAgent =
      typeof userAgent === 'string' && userAgent.length > 0
        ? userAgent
        : 'unknown';

    const trustScore = await this.trustScoreService.calculateTrustScore(
      req.userClaims.userId,
      normalizedDeviceId,
      ip,
      normalizedUserAgent,
    );

    return this.policyService.evaluateAccess(
      req.userClaims,
      trustScore.score,
      resource,
      action,
    );
  }
}