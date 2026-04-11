import { Controller, Get } from '@nestjs/common';
import { Public } from './public.decorator';

/**
 * Shallow health endpoint — returns {status, timestamp} with no pipeline overhead.
 * Decorated with @Public() so Phase 3's JwtAuthGuard skips authentication.
 * No DB or downstream checks: Phase 1 has no DB yet (per D-05).
 */
@Public()
@Controller('health')
export class HealthController {
  @Get()
  check(): { status: string; timestamp: string } {
    return { status: 'ok', timestamp: new Date().toISOString() };
  }
}
