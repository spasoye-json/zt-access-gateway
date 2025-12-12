import { Controller, Get, Query } from '@nestjs/common';
import { PolicyService } from './policy.service';
import { PolicyDecision } from '../shared/policy-evaluator.service';

@Controller('policy')
export class PolicyController {
  constructor(private readonly policyService: PolicyService) {}

  @Get('evaluate')
  async evaluatePolicy(
    @Query('userId') userId: string,
    @Query('resource') resource: string,
    @Query('action') action: string,
    @Query('riskScore') riskScore: number,
  ): Promise<PolicyDecision> {
    // In a real implementation, this would extract user claims from the authenticated user context
    const userClaims = { userId, roles: ['user'], sessionId: "" }; // Placeholder
    return this.policyService.evaluateAccess(userClaims, riskScore, resource, action);
  }
}