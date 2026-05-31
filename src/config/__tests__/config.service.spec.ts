// Set required env BEFORE importing config.module — ConfigModule.forRoot in @Module()
// evaluates the Joi schema immediately when the module file is first require()-d.
// Phase 8: PROXY_SERVICE_REGISTRY is now required; must be set before module load.
if (!process.env.PROXY_SERVICE_REGISTRY)
  process.env.PROXY_SERVICE_REGISTRY = JSON.stringify({
    dummy: 'https://dummy.test:8443',
  });
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

import { Test } from '@nestjs/testing';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { validationSchema as productionSchema } from '../config.module';
import {
  AUTH_CONFIG,
  HASHCASH_CONFIG,
  MFA_CONFIG,
  MTLS_CONFIG,
  POLICY_CONFIG,
  PROXY_CONFIG,
  AUDIT_CONFIG,
  SERVER_CONFIG,
  TRUST_CONFIG,
  buildAuthConfig,
  buildHashcashConfig,
  buildMfaConfig,
  buildMtlsConfig,
  buildPolicyConfig,
  buildProxyConfig,
  buildServerConfig,
  buildTrustConfig,
  buildAuditConfig,
  type AuthConfig,
  type HashcashConfig,
  type MfaConfig,
  type MtlsConfig,
  type PolicyConfig,
  type ProxyConfig,
  type ServerConfig,
  type TrustConfig,
  type AuditConfig,
} from '../slices';

// Helper: set all required env vars (mTLS + JWT + Phase 7 MFA + Phase 8 Proxy)
function setRequiredEnv() {
  process.env.MTLS_CA_CERT_PATH = '/tmp/ca.pem';
  process.env.MTLS_CLIENT_CERT_PATH = '/tmp/client.pem';
  process.env.MTLS_CLIENT_KEY_PATH = '/tmp/client-key.pem';
  process.env.MTLS_ALLOWED_SUBJECTS = 'test-cn';
  process.env.JWT_SECRET = 'test-secret-that-is-at-least-32-chars-long!';
  process.env.DATABASE_URL = 'postgresql://ztgateway:ztgateway@localhost:5432/ztgateway';
  process.env.HASHCASH_HMAC_SECRET = 'hashcash-secret-that-is-at-least-32-chars-long!';
  // Phase 7 MFA required vars (D-09, D-15)
  process.env.MFA_JWT_SECRET = 'mfa-secret-that-is-at-least-32-chars-long!!';
  process.env.MFA_TOTP_ENCRYPTION_KEY = Buffer.from('a'.repeat(32)).toString('base64');
  // Phase 8 Proxy required vars (D-03)
  if (!process.env.PROXY_SERVICE_REGISTRY)
    process.env.PROXY_SERVICE_REGISTRY = JSON.stringify({
      dummy: 'https://dummy.test:8443',
    });
}

/**
 * Bootstraps a real ConfigModule against the EXPORTED production Joi schema and
 * resolves a single slice token. Each invocation builds a fresh module so
 * per-test env mutations always re-run validation (`ignoreEnvFile: true`).
 */
async function resolveSlice<T>(token: symbol): Promise<T> {
  const module = await Test.createTestingModule({
    imports: [
      ConfigModule.forRoot({
        isGlobal: true,
        ignoreEnvFile: true,
        validationSchema: productionSchema,
        validationOptions: { abortEarly: false },
      }),
    ],
    providers: [
      { provide: AUTH_CONFIG, useFactory: buildAuthConfig, inject: [ConfigService] },
      { provide: MTLS_CONFIG, useFactory: buildMtlsConfig, inject: [ConfigService] },
      { provide: HASHCASH_CONFIG, useFactory: buildHashcashConfig, inject: [ConfigService] },
      { provide: TRUST_CONFIG, useFactory: buildTrustConfig, inject: [ConfigService] },
      { provide: POLICY_CONFIG, useFactory: buildPolicyConfig, inject: [ConfigService] },
      { provide: MFA_CONFIG, useFactory: buildMfaConfig, inject: [ConfigService] },
      { provide: PROXY_CONFIG, useFactory: buildProxyConfig, inject: [ConfigService] },
      { provide: AUDIT_CONFIG, useFactory: buildAuditConfig, inject: [ConfigService] },
      { provide: SERVER_CONFIG, useFactory: buildServerConfig, inject: [ConfigService] },
    ],
  }).compile();
  return module.get<T>(token);
}

async function bootValidationFailure(): Promise<void> {
  await Test.createTestingModule({
    imports: [
      ConfigModule.forRoot({
        isGlobal: true,
        ignoreEnvFile: true,
        validationSchema: productionSchema,
        validationOptions: { abortEarly: false },
      }),
    ],
  }).compile();
}

describe('ConfigAppModule slices', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    for (const key of Object.keys(process.env)) {
      if (!(key in originalEnv)) {
        delete process.env[key];
      }
    }
    Object.assign(process.env, originalEnv);
  });

  // ──────────────────────────────────────────────────────────────────────
  // Fail-fast Joi validation (CONF-01, D-11, D-21, D-23, D-03)
  // ──────────────────────────────────────────────────────────────────────
  describe('fail-fast Joi validation', () => {
    it('throws when MTLS_CA_CERT_PATH is missing', async () => {
      setRequiredEnv();
      delete process.env.MTLS_CA_CERT_PATH;
      await expect(bootValidationFailure()).rejects.toThrow();
    });

    it('lists ALL missing required mTLS vars at once (abortEarly: false)', async () => {
      delete process.env.MTLS_CA_CERT_PATH;
      delete process.env.MTLS_CLIENT_CERT_PATH;
      delete process.env.MTLS_CLIENT_KEY_PATH;
      delete process.env.MTLS_ALLOWED_SUBJECTS;
      let errorMessage = '';
      try {
        await bootValidationFailure();
      } catch (err: unknown) {
        errorMessage = err instanceof Error ? err.message : String(err);
      }
      expect(errorMessage).toContain('MTLS_CA_CERT_PATH');
      expect(errorMessage).toContain('MTLS_CLIENT_CERT_PATH');
      expect(errorMessage).toContain('MTLS_CLIENT_KEY_PATH');
      expect(errorMessage).toContain('MTLS_ALLOWED_SUBJECTS');
    });

    it('throws when JWT_SECRET is missing', async () => {
      setRequiredEnv();
      delete process.env.JWT_SECRET;
      await expect(bootValidationFailure()).rejects.toThrow();
    });

    it('throws when JWT_SECRET is shorter than 32 chars', async () => {
      setRequiredEnv();
      process.env.JWT_SECRET = 'too-short';
      await expect(bootValidationFailure()).rejects.toThrow();
    });

    it('throws when DATABASE_URL is missing', async () => {
      setRequiredEnv();
      delete process.env.DATABASE_URL;
      await expect(bootValidationFailure()).rejects.toThrow();
    });

    it('throws when HASHCASH_HMAC_SECRET is missing or short', async () => {
      setRequiredEnv();
      delete process.env.HASHCASH_HMAC_SECRET;
      await expect(bootValidationFailure()).rejects.toThrow();
    });

    it('throws when MFA_JWT_SECRET is absent', async () => {
      setRequiredEnv();
      delete process.env.MFA_JWT_SECRET;
      delete process.env.MFA_TOTP_ENCRYPTION_KEY;
      await expect(bootValidationFailure()).rejects.toThrow();
    });

    it('throws when MFA_JWT_SECRET length < 32 chars', async () => {
      setRequiredEnv();
      process.env.MFA_JWT_SECRET = 'short';
      await expect(bootValidationFailure()).rejects.toThrow();
    });

    it('throws when MFA_TOTP_ENCRYPTION_KEY does not base64-decode to 32 bytes', async () => {
      setRequiredEnv();
      // 45 chars but decodes to 33 bytes — passes a naive length check, fails AES-256.
      process.env.MFA_TOTP_ENCRYPTION_KEY = 'base64-encoded-32-byte-key-here-44-chars-xxx=';
      await expect(bootValidationFailure()).rejects.toThrow();
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // D-23 cross-field validator preserved verbatim — assert exact messages.
  // ──────────────────────────────────────────────────────────────────────
  describe('D-23 policy/threat cross-field validator', () => {
    it('accepts bootstrap with all defaults', async () => {
      setRequiredEnv();
      await expect(bootValidationFailure()).resolves.toBeUndefined();
    });

    it('rejects when Elevated challenge >= Normal challenge', async () => {
      setRequiredEnv();
      process.env.POLICY_ELEVATED_CHALLENGE_THRESHOLD = '0.5';
      let errMsg = '';
      try {
        await bootValidationFailure();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain(
        'POLICY_ELEVATED_CHALLENGE_THRESHOLD must be < POLICY_CHALLENGE_THRESHOLD',
      );
    });

    it('rejects when Critical challenge >= Elevated challenge', async () => {
      setRequiredEnv();
      process.env.POLICY_ELEVATED_CHALLENGE_THRESHOLD = '0.3';
      process.env.POLICY_CRITICAL_CHALLENGE_THRESHOLD = '0.4';
      let errMsg = '';
      try {
        await bootValidationFailure();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain(
        'POLICY_CRITICAL_CHALLENGE_THRESHOLD must be < POLICY_ELEVATED_CHALLENGE_THRESHOLD',
      );
    });

    it('rejects when Elevated deny >= Normal deny', async () => {
      setRequiredEnv();
      process.env.POLICY_ELEVATED_DENY_THRESHOLD = '0.8';
      let errMsg = '';
      try {
        await bootValidationFailure();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain('POLICY_ELEVATED_DENY_THRESHOLD must be < POLICY_DENY_THRESHOLD');
    });

    it('rejects when Critical deny >= Elevated deny', async () => {
      setRequiredEnv();
      process.env.POLICY_ELEVATED_DENY_THRESHOLD = '0.6';
      process.env.POLICY_CRITICAL_DENY_THRESHOLD = '0.7';
      let errMsg = '';
      try {
        await bootValidationFailure();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain(
        'POLICY_CRITICAL_DENY_THRESHOLD must be < POLICY_ELEVATED_DENY_THRESHOLD',
      );
    });

    it('rejects Elevated denies >= Critical denies', async () => {
      setRequiredEnv();
      process.env.THREAT_ELEVATED_DENIES = '50';
      process.env.THREAT_CRITICAL_DENIES = '20';
      let errMsg = '';
      try {
        await bootValidationFailure();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain('THREAT_ELEVATED_DENIES must be < THREAT_CRITICAL_DENIES');
    });

    it('rejects Elevated invalid_tokens >= Critical invalid_tokens', async () => {
      setRequiredEnv();
      process.env.THREAT_ELEVATED_INVALID_TOKENS = '80';
      process.env.THREAT_CRITICAL_INVALID_TOKENS = '30';
      let errMsg = '';
      try {
        await bootValidationFailure();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain(
        'THREAT_ELEVATED_INVALID_TOKENS must be < THREAT_CRITICAL_INVALID_TOKENS',
      );
    });

    it('rejects Elevated honeypot >= Critical honeypot', async () => {
      setRequiredEnv();
      process.env.THREAT_ELEVATED_HONEYPOT = '15';
      process.env.THREAT_CRITICAL_HONEYPOT = '5';
      let errMsg = '';
      try {
        await bootValidationFailure();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain('THREAT_ELEVATED_HONEYPOT must be < THREAT_CRITICAL_HONEYPOT');
    });

    it('rejects Elevated mfa_rate_limited >= Critical mfa_rate_limited (14-03)', async () => {
      setRequiredEnv();
      process.env.THREAT_ELEVATED_MFA_RATE_LIMITED = '15';
      process.env.THREAT_CRITICAL_MFA_RATE_LIMITED = '5';
      let errMsg = '';
      try {
        await bootValidationFailure();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain(
        'THREAT_ELEVATED_MFA_RATE_LIMITED must be < THREAT_CRITICAL_MFA_RATE_LIMITED',
      );
    });

    it('rejects POLICY_CHALLENGE_THRESHOLD outside [0,1]', async () => {
      setRequiredEnv();
      process.env.POLICY_CHALLENGE_THRESHOLD = '1.5';
      await expect(bootValidationFailure()).rejects.toThrow();
    });

    it('rejects THREAT_WINDOW_MS below 1000', async () => {
      setRequiredEnv();
      process.env.THREAT_WINDOW_MS = '500';
      await expect(bootValidationFailure()).rejects.toThrow();
    });

    it('rejects MFA_CHALLENGE_TTL_MS >= MFA_TOKEN_TTL_MS', async () => {
      setRequiredEnv();
      process.env.MFA_CHALLENGE_TTL_MS = '300000';
      process.env.MFA_TOKEN_TTL_MS = '300000';
      let errMsg = '';
      try {
        await bootValidationFailure();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain('MFA_CHALLENGE_TTL_MS must be < MFA_TOKEN_TTL_MS');
    });
  });

  // ──────────────────────────────────────────────────────────────────────
  // Slice factory smoke — each slice returns the expected shape and is FROZEN.
  // ──────────────────────────────────────────────────────────────────────
  describe('slice factories', () => {
    it('AuthConfig: required field + optionals undefined when env not set', async () => {
      setRequiredEnv();
      const slice = await resolveSlice<AuthConfig>(AUTH_CONFIG);
      expect(slice.jwtSecret).toBe('test-secret-that-is-at-least-32-chars-long!');
      expect(slice.jwtPublicKey).toBeUndefined();
      expect(slice.jwksUri).toBeUndefined();
      expect(slice.jwtIssuer).toBeUndefined();
      expect(slice.jwtAudience).toBeUndefined();
      expect(Object.isFrozen(slice)).toBe(true);
    });

    it('MtlsConfig: allowedSubjects split from comma-separated env', async () => {
      setRequiredEnv();
      process.env.MTLS_ALLOWED_SUBJECTS = 'cn1,cn2,cn3';
      const slice = await resolveSlice<MtlsConfig>(MTLS_CONFIG);
      expect(slice.allowedSubjects).toEqual(['cn1', 'cn2', 'cn3']);
      expect(Object.isFrozen(slice)).toBe(true);
    });

    it('HashcashConfig: defaults + env override', async () => {
      setRequiredEnv();
      process.env.HASHCASH_DIFFICULTY_MIN = '4';
      process.env.HASHCASH_DIFFICULTY_MAX = '4';
      const slice = await resolveSlice<HashcashConfig>(HASHCASH_CONFIG);
      expect(slice.hmacSecret).toBe('hashcash-secret-that-is-at-least-32-chars-long!');
      expect(slice.challengeTtlMs).toBe(120000);
      expect(slice.usedNonceCapacity).toBe(10000);
      expect(slice.triggerThreshold).toBe(0.7);
      expect(slice.difficultyMin).toBe(4);
      expect(slice.difficultyMax).toBe(4);
      expect(Object.isFrozen(slice)).toBe(true);
    });

    it('TrustConfig: all 5 fields default', async () => {
      setRequiredEnv();
      const slice = await resolveSlice<TrustConfig>(TRUST_CONFIG);
      expect(slice.knownThreshold).toBe(3);
      expect(slice.decayHalfLifeMs).toBe(604800000);
      expect(slice.anomalyWarmupN).toBe(20);
      expect(slice.frequencyWindowMs).toBe(60000);
      expect(slice.frequencyNormalMax).toBe(30);
      expect(Object.isFrozen(slice)).toBe(true);
    });

    it('PolicyConfig: paths default + 6 thresholds default + threat counts default', async () => {
      setRequiredEnv();
      const slice = await resolveSlice<PolicyConfig>(POLICY_CONFIG);
      expect(slice.modelPath).toBe('policy/model.conf');
      expect(slice.csvPath).toBe('policy/policy.csv');
      expect(slice.challengeThreshold).toBe(0.5);
      expect(slice.denyThreshold).toBe(0.8);
      expect(slice.elevatedChallengeThreshold).toBe(0.3);
      expect(slice.elevatedDenyThreshold).toBe(0.6);
      expect(slice.criticalChallengeThreshold).toBe(0.2);
      expect(slice.criticalDenyThreshold).toBe(0.4);
      expect(slice.threatWindowMs).toBe(300000);
      expect(slice.threatWindowMaxEvents).toBe(10000);
      expect(slice.threatCooldownMs).toBe(600000);
      expect(slice.threatElevatedDenies).toBe(20);
      expect(slice.threatCriticalDenies).toBe(50);
      expect(slice.threatElevatedInvalidTokens).toBe(30);
      expect(slice.threatCriticalInvalidTokens).toBe(80);
      expect(slice.threatElevatedHoneypot).toBe(5);
      expect(slice.threatCriticalHoneypot).toBe(15);
      expect(slice.threatElevatedMfaRateLimited).toBe(5);
      expect(slice.threatCriticalMfaRateLimited).toBe(15);
      expect(Object.isFrozen(slice)).toBe(true);
    });

    it('PolicyConfig: env override flows through (POLICY_DENY_THRESHOLD)', async () => {
      setRequiredEnv();
      process.env.POLICY_DENY_THRESHOLD = '0.95';
      const slice = await resolveSlice<PolicyConfig>(POLICY_CONFIG);
      expect(slice.denyThreshold).toBe(0.95);
    });

    it('PolicyConfig: env override flows through (THREAT_ELEVATED_DENIES)', async () => {
      setRequiredEnv();
      process.env.THREAT_ELEVATED_DENIES = '10';
      const slice = await resolveSlice<PolicyConfig>(POLICY_CONFIG);
      expect(slice.threatElevatedDenies).toBe(10);
    });

    it('MfaConfig: all 8 fields populated from validated env', async () => {
      setRequiredEnv();
      process.env.MFA_CHALLENGE_TTL_MS = '300000';
      process.env.MFA_TOKEN_TTL_MS = '600000';
      const slice = await resolveSlice<MfaConfig>(MFA_CONFIG);
      expect(slice.jwtSecret).toBe('mfa-secret-that-is-at-least-32-chars-long!!');
      expect(slice.totpEncryptionKey).toBe(Buffer.from('a'.repeat(32)).toString('base64'));
      expect(slice.challengeTtlMs).toBe(300000);
      expect(slice.tokenTtlMs).toBe(600000);
      expect(slice.rateLimitMax).toBe(5);
      expect(slice.rateLimitWindowMs).toBe(60000);
      expect(slice.issuerName).toBe('ZT-Gateway');
      expect(slice.enrollPendingTtlMs).toBe(600000);
      expect(Object.isFrozen(slice)).toBe(true);
    });

    it('ProxyConfig: serviceRegistry raw JSON + circuit-breaker defaults', async () => {
      setRequiredEnv();
      const slice = await resolveSlice<ProxyConfig>(PROXY_CONFIG);
      expect(JSON.parse(slice.serviceRegistry)).toEqual({ dummy: 'https://dummy.test:8443' });
      expect(slice.cbVolumeThreshold).toBe(5);
      expect(slice.cbErrorThreshold).toBe(50);
      expect(slice.cbResetTimeout).toBe(10000);
      expect(slice.maxRetries).toBe(3);
      expect(slice.boplaPolicyPath).toBe('policy/field-policy.json');
      expect(Object.isFrozen(slice)).toBe(true);
    });

    it('AuditConfig: WAL defaults', async () => {
      setRequiredEnv();
      const slice = await resolveSlice<AuditConfig>(AUDIT_CONFIG);
      expect(slice.walBaseDelayMs).toBe(50);
      expect(slice.walMaxRetries).toBe(3);
      expect(Object.isFrozen(slice)).toBe(true);
    });

    it('ServerConfig: runtime fields default + honeypotRoutes empty array on unset env', async () => {
      setRequiredEnv();
      delete process.env.HONEYPOT_ROUTES;
      const slice = await resolveSlice<ServerConfig>(SERVER_CONFIG);
      expect(slice.port).toBe(3000);
      // NODE_ENV in jest runtime is 'test'; Joi accepts 'test' as valid.
      expect(['development', 'test', 'production']).toContain(slice.nodeEnv);
      expect(slice.corsOrigin).toBe('*');
      expect(slice.rateLimitWindowMs).toBe(60000);
      expect(slice.rateLimitMax).toBe(100);
      expect(slice.databaseUrl).toBe('postgresql://ztgateway:ztgateway@localhost:5432/ztgateway');
      expect(slice.blacklistTtlMs).toBe(3600000);
      expect(slice.honeypotRoutes).toEqual([]);
      expect(Object.isFrozen(slice)).toBe(true);
    });

    it('ServerConfig: honeypotRoutes parses JSON array from env', async () => {
      setRequiredEnv();
      process.env.HONEYPOT_ROUTES = JSON.stringify(['/foo', '/bar']);
      const slice = await resolveSlice<ServerConfig>(SERVER_CONFIG);
      expect(slice.honeypotRoutes).toEqual(['/foo', '/bar']);
    });

    it('ServerConfig: honeypotRoutes falls back to [] on malformed JSON', async () => {
      setRequiredEnv();
      process.env.HONEYPOT_ROUTES = 'not-json';
      const slice = await resolveSlice<ServerConfig>(SERVER_CONFIG);
      expect(slice.honeypotRoutes).toEqual([]);
    });

    it('hashcash hmacSecret is distinct from auth jwtSecret (D-05 separation)', async () => {
      setRequiredEnv();
      process.env.JWT_SECRET = 'jwt-secret-that-is-at-least-32-chars-long-AAAA';
      process.env.HASHCASH_HMAC_SECRET = 'hashcash-secret-that-is-at-least-32-chars-long-BBBB';
      const auth = await resolveSlice<AuthConfig>(AUTH_CONFIG);
      const hc = await resolveSlice<HashcashConfig>(HASHCASH_CONFIG);
      expect(hc.hmacSecret).not.toBe(auth.jwtSecret);
    });
  });
});
