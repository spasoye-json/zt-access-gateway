/**
 * Phase 6 Plan 06 — D-03 fail-closed startup (PLCY-01).
 *
 * W4: dedicated file so module reload with jest.resetModules() does not
 * contaminate the main policy.e2e.spec.ts AppModule cache (Pitfall 7 isolation
 * at the worker level).
 */

describe('Policy E2E — fail-closed startup (D-03)', () => {
  it('PLCY-01: bogus POLICY_MODEL_PATH rejects bootstrap', async () => {
    const origModel = process.env.POLICY_MODEL_PATH;
    const origCsv = process.env.POLICY_CSV_PATH;

    // Set env BEFORE the dynamic AppModule import.
    process.env.NODE_ENV = 'test';
    process.env.JWT_SECRET =
      process.env.JWT_SECRET ?? 'test-secret-that-is-at-least-32-chars-long!';
    process.env.HASHCASH_HMAC_SECRET =
      process.env.HASHCASH_HMAC_SECRET ?? 'a'.repeat(64);
    process.env.HASHCASH_DIFFICULTY_MIN =
      process.env.HASHCASH_DIFFICULTY_MIN ?? '4';
    process.env.HASHCASH_DIFFICULTY_MAX =
      process.env.HASHCASH_DIFFICULTY_MAX ?? '4';
    if (!process.env.MTLS_CA_CERT_PATH)
      process.env.MTLS_CA_CERT_PATH = '/dev/null';
    if (!process.env.MTLS_CLIENT_CERT_PATH)
      process.env.MTLS_CLIENT_CERT_PATH = '/dev/null';
    if (!process.env.MTLS_CLIENT_KEY_PATH)
      process.env.MTLS_CLIENT_KEY_PATH = '/dev/null';
    if (!process.env.MTLS_ALLOWED_SUBJECTS)
      process.env.MTLS_ALLOWED_SUBJECTS = 'cn=test';
    if (!process.env.DATABASE_URL)
      process.env.DATABASE_URL = 'postgresql://localhost:5432/zt_test';
    // Phase 7 MFA vars — required by config validation after MfaModule added to AppModule
    if (!process.env.MFA_JWT_SECRET)
      process.env.MFA_JWT_SECRET = 'mfa-test-secret-that-is-at-least-32-chars!!';
    if (!process.env.MFA_TOTP_ENCRYPTION_KEY)
      process.env.MFA_TOTP_ENCRYPTION_KEY = Buffer.from('a'.repeat(32)).toString('base64');
    process.env.POLICY_MODEL_PATH = '/no/such/model.conf';
    process.env.POLICY_CSV_PATH = '/no/such/policy.csv';

    // CRITICAL: reset the module registry so AppModule is constructed fresh
    // against the bogus env (modules cached during prior tests would otherwise
    // resolve POLICY_* via stale ConfigModule state).
    jest.resetModules();

    let err: unknown;
    try {
      const { Test } = await import('@nestjs/testing');
      const { AppModule } = await import('../../app.module');
      const { TrustScoreService } = await import(
        '../../trust-score/trust-score.service'
      );

      const ref = await Test.createTestingModule({ imports: [AppModule] })
        .overrideProvider(TrustScoreService)
        .useValue({
          evaluateScore: jest.fn().mockResolvedValue(0.1),
          recordTrustContextAfterAllow: jest.fn(),
        })
        .compile();
      const inst = ref.createNestApplication();
      await inst.init();
      await inst.close();
    } catch (e) {
      err = e;
    } finally {
      // Restore env (Pitfall 7 isolation hygiene)
      if (origModel === undefined) delete process.env.POLICY_MODEL_PATH;
      else process.env.POLICY_MODEL_PATH = origModel;
      if (origCsv === undefined) delete process.env.POLICY_CSV_PATH;
      else process.env.POLICY_CSV_PATH = origCsv;
    }

    expect(err).toBeDefined();
  });
});
