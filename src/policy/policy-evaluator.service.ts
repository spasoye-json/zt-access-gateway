import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { newEnforcer, type Enforcer } from 'casbin';
import { join } from 'path';

export interface PolicyDecision {
  decision: 'ALLOW' | 'DENY' | 'CHALLENGE';
  reason: string;
  score?: number;
}

@Injectable()
export class PolicyEvaluatorService implements OnModuleInit {
  private readonly logger = new Logger(PolicyEvaluatorService.name);
  private enforcer: Enforcer | null = null;

  constructor(private configService: ConfigService) {}

  async onModuleInit() {
    const modelPath =
      this.configService.get<string>('POLICY_MODEL_PATH') ||
      join(process.cwd(), 'policy', 'model.conf');
    const policyPath =
      this.configService.get<string>('POLICY_POLICY_PATH') ||
      join(process.cwd(), 'policy', 'policy.csv');

    this.enforcer = await newEnforcer(modelPath, policyPath);
    this.logger.log(`Policy engine loaded model=${modelPath} policy=${policyPath}`);
  }

  private async ensureReady(): Promise<Enforcer> {
    if (this.enforcer) return this.enforcer;
    await this.onModuleInit();
    if (!this.enforcer) {
      throw new Error('Policy engine failed to initialize');
    }
    return this.enforcer;
  }

  async listPolicies(): Promise<string[][]> {
    const enforcer = await this.ensureReady();
    return enforcer.getPolicy();
  }

  async addPolicy(subject: string, resource: string, action: string): Promise<boolean> {
    const enforcer = await this.ensureReady();
    const added = await enforcer.addPolicy(subject, resource, action);
    if (added) {
      await this.persistPolicies(enforcer);
    }
    return added;
  }

  async removePolicy(subject: string, resource: string, action: string): Promise<boolean> {
    const enforcer = await this.ensureReady();
    const removed = await enforcer.removePolicy(subject, resource, action);
    if (removed) {
      await this.persistPolicies(enforcer);
    }
    return removed;
  }

  async reloadPolicies(): Promise<void> {
    const enforcer = await this.ensureReady();
    await enforcer.loadPolicy();
  }

  // Evaluates authorization (Casbin) + risk-based decision (deny/challenge/allow)
  async evaluatePolicies(
    userClaims: any,
    riskScore: number,
    resource: string,
    action: string
  ): Promise<PolicyDecision> {
    const denyThreshold = Number(
      this.configService.get('POLICY_DENY_RISK_THRESHOLD') ?? 0.8,
    );
    const challengeThreshold = Number(
      this.configService.get('POLICY_CHALLENGE_RISK_THRESHOLD') ?? 0.5,
    );

    const resourcePath = typeof resource === 'string' ? resource.split('?')[0] : '';
    const method = typeof action === 'string' ? action.toUpperCase() : '';

    const userId = userClaims?.userId;
    const roles = Array.isArray(userClaims?.roles) ? userClaims.roles : [];

    const subjects: string[] = [];
    if (typeof userId === 'string' && userId) {
      subjects.push(`user:${userId}`);
    }
    for (const role of roles) {
      if (typeof role === 'string' && role) {
        subjects.push(`role:${role}`);
      }
    }

    if (!subjects.length) {
      return { decision: 'DENY', reason: 'Unauthenticated subject' };
    }

    const enforcer = await this.ensureReady();

    let authorized = false;
    for (const sub of subjects) {
      if (await enforcer.enforce(sub, resourcePath, method)) {
        authorized = true;
        break;
      }
    }

    if (!authorized) {
      return { decision: 'DENY', reason: 'Policy denied' };
    }

    if (typeof riskScore !== 'number' || Number.isNaN(riskScore)) {
      return { decision: 'DENY', reason: 'Invalid risk score' };
    }

    if (riskScore > denyThreshold) {
      return { decision: 'DENY', reason: 'Risk score too high', score: riskScore };
    }
    if (riskScore > challengeThreshold) {
      return {
        decision: 'CHALLENGE',
        reason: 'Medium risk score requires additional verification',
        score: riskScore,
      };
    }

    return { decision: 'ALLOW', reason: 'Authorized and low risk', score: riskScore };
  }

  private async persistPolicies(enforcer: Enforcer): Promise<void> {
    try {
      await enforcer.savePolicy();
    } catch (error) {
      this.logger.warn(`Failed to persist policy changes: ${error.message}`);
    }
  }
}
