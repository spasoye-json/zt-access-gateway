/** Minimum env to satisfy Joi schema so ConfigAppModule compiles. */
function applyBaseEnv(): void {
  Object.assign(process.env, {
    NODE_ENV: 'test',
    JWT_SECRET: 'test-secret-that-is-at-least-32-chars-long!',
    HASHCASH_HMAC_SECRET: 'a'.repeat(64),
    MTLS_CA_CERT_PATH: '/dev/null',
    MTLS_CLIENT_CERT_PATH: '/dev/null',
    MTLS_CLIENT_KEY_PATH: '/dev/null',
    MTLS_ALLOWED_SUBJECTS: 'cn=test',
    DATABASE_URL: 'postgresql://localhost:5432/zt_test',
    MFA_JWT_SECRET: 'mfa-test-secret-that-is-at-least-32-chars!!',
    MFA_TOTP_ENCRYPTION_KEY: Buffer.from('a'.repeat(32)).toString('base64'),
    PROXY_SERVICE_REGISTRY: JSON.stringify({ svc: 'https://svc.test:8443' }),
    BOPLA_POLICY_PATH: 'policy/field-policy.json',
  });
}

describe('AuditModule wiring (AUDT-06)', () => {
  it('compiles, registers AuditController, exports AuditService', async () => {
    applyBaseEnv();
    jest.resetModules();

    const { Test } = await import('@nestjs/testing');
    const { AuditModule } = await import('../audit.module');
    const { AuditService } = await import('../audit.service');
    const { AuditRepository } = await import('../audit.repository');
    const { AuditController } = await import('../audit.controller');

    const moduleRef = await Test.createTestingModule({ imports: [AuditModule] })
      .overrideProvider(AuditRepository)
      .useValue({
        insert: jest.fn(),
        findLogs: jest.fn(),
        onModuleDestroy: jest.fn(),
      })
      .compile();

    expect(moduleRef.get(AuditService, { strict: false })).toBeInstanceOf(AuditService);
    expect(moduleRef.get(AuditController, { strict: false })).toBeInstanceOf(AuditController);
    await moduleRef.close();
  }, 15000);
});
