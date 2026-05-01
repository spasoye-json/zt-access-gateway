/**
 * E2e test setup -- sets required env vars before any module imports.
 * ConfigModule.forRoot() validates at decoration time, so env vars must
 * exist before the test file's import of AppModule is resolved.
 */
process.env.JWT_SECRET = 'test-secret-that-is-at-least-32-chars-long!';
process.env.MTLS_CA_CERT_PATH = '/tmp/test-ca.pem';
process.env.MTLS_CLIENT_CERT_PATH = '/tmp/test-client.pem';
process.env.MTLS_CLIENT_KEY_PATH = '/tmp/test-client-key.pem';
process.env.MTLS_ALLOWED_SUBJECTS = 'test-cn';
// Phase 7 MFA vars — required by config validation after MfaModule added to AppModule
process.env.MFA_JWT_SECRET =
  process.env.MFA_JWT_SECRET ?? 'mfa-test-secret-that-is-at-least-32-chars!!';
process.env.MFA_TOTP_ENCRYPTION_KEY =
  process.env.MFA_TOTP_ENCRYPTION_KEY ?? Buffer.from('a'.repeat(32)).toString('base64');
