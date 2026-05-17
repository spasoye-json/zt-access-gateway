import { DemoMfaModule } from '../demo-mfa.module';
import { DemoMfaController } from '../demo-mfa.controller';

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
});
