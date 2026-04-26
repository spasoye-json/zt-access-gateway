import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import { Roles } from '../auth/roles.decorator';
import { PolicyEvaluatorService } from './policy-evaluator.service';
import { ThreatEscalationService } from './threat-escalation.service';
import { PolicyRuleDto } from './dto/policy-rule.dto';
import { EscalationLevelDto } from './dto/escalation-level.dto';

/**
 * Phase 6 — Admin controller for Casbin rules CRUD + threat-escalation override
 * (D-22, PLCY-06, PLCY-11).
 *
 * All endpoints are class-level @Roles('admin') — RolesGuard is the global
 * APP_GUARD wired in Phase 3. Mutation endpoints delegate to
 * PolicyEvaluatorService.addRule/removeRule, which serialize through a writer
 * mutex (D-02) and throw if FileAdapter.savePolicy() returns false (Pitfall 1).
 *
 * Body convention (D-22 Claude's Discretion): structured-only — no string
 * literal bodies; class-validator DTOs reject empty fields and invalid level
 * values via the global ValidationPipe (Phase 1 bootstrap).
 */
@Controller('policy/admin')
@Roles('admin')
export class PolicyAdminController {
  constructor(
    private readonly evaluator: PolicyEvaluatorService,
    private readonly threat: ThreatEscalationService,
  ) {}

  // ── Rules CRUD (PLCY-06) ──

  @Get('rules')
  async listRules(): Promise<{ rules: string[][] }> {
    return { rules: await this.evaluator.getRules() };
  }

  @Post('rules')
  @HttpCode(HttpStatus.OK)
  async addRule(@Body() dto: PolicyRuleDto): Promise<{ added: boolean }> {
    const added = await this.evaluator.addRule(dto.sub, dto.obj, dto.act);
    return { added };
  }

  @Delete('rules')
  @HttpCode(HttpStatus.OK)
  async removeRule(@Body() dto: PolicyRuleDto): Promise<{ removed: boolean }> {
    const removed = await this.evaluator.removeRule(dto.sub, dto.obj, dto.act);
    return { removed };
  }

  // ── Threat-escalation introspection + override (PLCY-11) ──

  @Get('escalation')
  getEscalation(): ReturnType<ThreatEscalationService['snapshot']> {
    return this.threat.snapshot();
  }

  @Post('escalation')
  @HttpCode(HttpStatus.OK)
  setEscalation(@Body() dto: EscalationLevelDto): {
    ok: true;
    level: typeof dto.level;
  } {
    this.threat.setManualLevel(dto.level);
    return { ok: true, level: dto.level };
  }

  @Delete('escalation')
  @HttpCode(HttpStatus.OK)
  clearEscalation(): { ok: true } {
    this.threat.clearManualLevel();
    return { ok: true };
  }
}
