import { Injectable } from '@nestjs/common';
import {
  PolicyEvaluatorService,
  PolicyDecision,
} from './policy-evaluator.service';
import { UserClaims } from '../auth/auth.service';

export interface PolicyBinding {
  subject: string;
  resource: string;
  action: string;
}

@Injectable()
export class PolicyService {
  constructor(private policyEvaluator: PolicyEvaluatorService) {}

  async evaluateAccess(
    userClaims: UserClaims,
    riskScore: number,
    resource: string,
    action: string
  ): Promise<PolicyDecision> {
    return this.policyEvaluator.evaluatePolicies(userClaims, riskScore, resource, action);
  }

  async listPolicies(): Promise<PolicyBinding[]> {
    const policies = await this.policyEvaluator.listPolicies();
    return policies.map(([subject, resource, action]) => ({
      subject,
      resource,
      action,
    }));
  }

  async addPolicy(binding: PolicyBinding): Promise<boolean> {
    return this.policyEvaluator.addPolicy(binding.subject, binding.resource, binding.action);
  }

  async removePolicy(binding: PolicyBinding): Promise<boolean> {
    return this.policyEvaluator.removePolicy(binding.subject, binding.resource, binding.action);
  }

  async reloadPolicies(): Promise<void> {
    await this.policyEvaluator.reloadPolicies();
  }
}
