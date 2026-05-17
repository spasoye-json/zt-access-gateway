import { DynamicModule, Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { MfaModule } from '../mfa/mfa.module';
import { DemoMfaController } from './demo-mfa.controller';

/**
 * Slice E (#6) — Dynamic module that conditionally registers DemoMfaController
 * based on the DEMO_MODE env flag at module-bootstrap time.
 *
 * When DEMO_MODE !== 'true' the controller is omitted entirely so
 * POST /demo/mfa-token returns 404 instead of being gated by a runtime guard.
 * The strict-equality check on the string `'true'` mirrors DemoModeService so
 * the two gates can never disagree on what "active" means (PRD #1 story 32).
 */
@Module({})
export class DemoMfaModule {
  static forRoot(): DynamicModule {
    const active = process.env.DEMO_MODE === 'true';
    return {
      module: DemoMfaModule,
      imports: [AuthModule, MfaModule],
      controllers: active ? [DemoMfaController] : [],
    };
  }
}
