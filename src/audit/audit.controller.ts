import { Controller, Get, Query } from '@nestjs/common';
import { Roles } from '../auth/roles.decorator';
import { AuditService } from './audit.service';
import { AuditLogsQueryDto } from './dto/audit-logs-query.dto';
import type { AuditLog } from './audit-log.interface';

/**
 * Phase 9 — Audit query endpoint (AUDT-05, D-07, D-08).
 *
 * Class-level @Roles('admin') — RolesGuard is the global APP_GUARD wired in
 * Phase 3 (mirrors PolicyAdminController). Validation via global ValidationPipe
 * + AuditLogsQueryDto (Phase 1 bootstrap).
 */
@Controller('audit')
@Roles('admin')
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Get('logs')
  async getLogs(
    @Query() query: AuditLogsQueryDto,
  ): Promise<{ items: AuditLog[]; total: number }> {
    return this.auditService.queryLogs(query);
  }
}
