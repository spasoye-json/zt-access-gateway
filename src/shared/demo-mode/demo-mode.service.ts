import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * Single source of truth for the `DEMO_MODE` env flag.
 *
 * Other modules MUST consult `isActive()` instead of reading `process.env`
 * directly so the demo-mode boundary is auditable in one file (parent PRD,
 * #1 user story 32). Strict-equality check on `"true"` keeps the flag from
 * silently activating on `"false"`, `"1"`, or empty strings.
 */
@Injectable()
export class DemoModeService {
  private readonly active: boolean;

  constructor(config: ConfigService) {
    this.active = config.get<string>('DEMO_MODE') === 'true';
  }

  isActive(): boolean {
    return this.active;
  }
}
