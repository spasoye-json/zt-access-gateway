import { DemoMfaModule } from '../demo-mfa.module';
import { DemoMfaController } from '../demo-mfa.controller';
import { SharedModule } from '../../shared/shared.module';
import { AuthModule } from '../../auth/auth.module';
import { MfaModule } from '../../mfa/mfa.module';

describe('DemoMfaModule.forRoot()', () => {
  const originalDemoMode = process.env.DEMO_MODE;

  afterEach(() => {
    if (originalDemoMode === undefined) delete process.env.DEMO_MODE;
    else process.env.DEMO_MODE = originalDemoMode;
  });

  it('registers DemoMfaController when DEMO_MODE=true', () => {
    process.env.DEMO_MODE = 'true';
    const dyn = DemoMfaModule.forRoot();
    expect(dyn.controllers).toEqual([DemoMfaController]);
  });

  it('does NOT register DemoMfaController when DEMO_MODE is unset (route 404s)', () => {
    delete process.env.DEMO_MODE;
    const dyn = DemoMfaModule.forRoot();
    expect(dyn.controllers ?? []).toEqual([]);
  });

  it('does NOT register DemoMfaController when DEMO_MODE=false', () => {
    process.env.DEMO_MODE = 'false';
    const dyn = DemoMfaModule.forRoot();
    expect(dyn.controllers ?? []).toEqual([]);
  });

  it('ignores truthy-looking-but-non-"true" values to mirror DemoModeService semantics', () => {
    process.env.DEMO_MODE = '1';
    const dyn = DemoMfaModule.forRoot();
    expect(dyn.controllers ?? []).toEqual([]);
  });

  it('imports SharedModule so JwtAuthGuard.TypedEvents resolves at runtime', () => {
    // Regression: the unit test for DemoMfaController overrides JwtAuthGuard,
    // which hid that DemoMfaModule originally didn't import SharedModule —
    // the runtime then failed with "Nest can't resolve TypedEvents". A full
    // module compile() would surface this too but pulls in the DbModule
    // (Symbol(DB) provider) which requires Postgres. Asserting on the imports
    // list keeps the contract honest without needing a DB.
    process.env.DEMO_MODE = 'true';
    const dyn = DemoMfaModule.forRoot();
    expect(dyn.imports).toEqual(expect.arrayContaining([SharedModule, AuthModule, MfaModule]));
  });
});
