import { Controller, Get } from '@nestjs/common';
import { AuditService } from './audit.service';
import { Public } from '../auth/public.decorator';

@Public()
@Controller('audit')
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Get('health')
  healthCheck(): string {
    return 'Audit service is running';
  }
}
