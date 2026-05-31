// Set required env BEFORE importing the modules below — AuthModule transitively
// requires config.module.ts, whose ConfigModule.forRoot() evaluates its Joi
// schema eagerly at require() time. Guards let a real .env / CI env win. Mirrors
// the canonical defaults in src/config/__tests__/config.service.spec.ts.
if (!process.env.PROXY_SERVICE_REGISTRY)
  process.env.PROXY_SERVICE_REGISTRY = JSON.stringify({ dummy: 'https://dummy.test:8443' });
if (!process.env.MTLS_CA_CERT_PATH) process.env.MTLS_CA_CERT_PATH = '/dev/null';
if (!process.env.MTLS_CLIENT_CERT_PATH) process.env.MTLS_CLIENT_CERT_PATH = '/dev/null';
if (!process.env.MTLS_CLIENT_KEY_PATH) process.env.MTLS_CLIENT_KEY_PATH = '/dev/null';
if (!process.env.MTLS_ALLOWED_SUBJECTS) process.env.MTLS_ALLOWED_SUBJECTS = 'cn=test';
if (!process.env.JWT_SECRET) process.env.JWT_SECRET = 'test-secret-that-is-at-least-32-chars-long!';
if (!process.env.DATABASE_URL) process.env.DATABASE_URL = 'postgresql://localhost:5432/zt_test';
if (!process.env.HASHCASH_HMAC_SECRET) process.env.HASHCASH_HMAC_SECRET = 'a'.repeat(64);
if (!process.env.MFA_JWT_SECRET)
  process.env.MFA_JWT_SECRET = 'mfa-test-secret-that-is-at-least-32-chars!!';
if (!process.env.MFA_TOTP_ENCRYPTION_KEY)
  process.env.MFA_TOTP_ENCRYPTION_KEY = Buffer.from('a'.repeat(32)).toString('base64');

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
