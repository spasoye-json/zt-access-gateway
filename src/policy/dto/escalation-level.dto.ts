import { IsIn } from 'class-validator';
import type { ThreatLevel } from '../threat-escalation.service';

/**
 * Phase 6 — Body DTO for POST /policy/admin/escalation (PLCY-11).
 * `level` must be one of the three ThreatLevel literals.
 */
export class EscalationLevelDto {
  @IsIn(['Normal', 'Elevated', 'Critical'])
  level!: ThreatLevel;
}
