import { Injectable } from '@nestjs/common';
import { AppConfigService } from '../config/config.service';
import { PolicyMetrics } from './policy-metrics';

/**
 * Phase 6 — ThreatEscalationService stub (full implementation in Plan 06-03).
 *
 * Plan 02 only consumes the read-side contract (currentChallengeThreshold /
 * currentDenyThreshold) inside PolicyEvaluatorService. Plan 03 will replace
 * this file with the full sliding-window aggregator + @OnEvent subscribers
 * + manual override + transition logging (D-13..D-22).
 *
 * Until Plan 03 lands, this stub returns the NORMAL-level thresholds from
 * AppConfigService so Plan 02 can compose, compile, and unit-test under
 * fail-closed semantics. Plan 03 will overwrite this file completely.
 */
@Injectable()
export class ThreatEscalationService {
  constructor(
    protected readonly cfg: AppConfigService,
    protected readonly metrics: PolicyMetrics,
  ) {}

  currentChallengeThreshold(): number {
    return this.cfg.policyChallengeThreshold;
  }

  currentDenyThreshold(): number {
    return this.cfg.policyDenyThreshold;
  }
}
