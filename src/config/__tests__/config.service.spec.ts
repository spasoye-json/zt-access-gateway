import { Test } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import * as Joi from 'joi';
import { AppConfigService } from '../config.service';
import { ConfigAppModule } from '../config.module';

// Helper: set all required env vars (mTLS + JWT)
function setRequiredEnv() {
  process.env.MTLS_CA_CERT_PATH = '/tmp/ca.pem';
  process.env.MTLS_CLIENT_CERT_PATH = '/tmp/client.pem';
  process.env.MTLS_CLIENT_KEY_PATH = '/tmp/client-key.pem';
  process.env.MTLS_ALLOWED_SUBJECTS = 'test-cn';
  process.env.JWT_SECRET = 'test-secret-that-is-at-least-32-chars-long!';
  process.env.DATABASE_URL =
    'postgresql://ztgateway:ztgateway@localhost:5432/ztgateway';
  process.env.HASHCASH_HMAC_SECRET =
    'hashcash-secret-that-is-at-least-32-chars-long!';
}

const joiSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
  PORT: Joi.number().default(3000),
  CORS_ORIGIN: Joi.string().default('*'),
  RATE_LIMIT_WINDOW_MS: Joi.number().default(60000),
  RATE_LIMIT_MAX: Joi.number().default(100),
  MTLS_CA_CERT_PATH: Joi.string().required(),
  MTLS_CLIENT_CERT_PATH: Joi.string().required(),
  MTLS_CLIENT_KEY_PATH: Joi.string().required(),
  MTLS_ALLOWED_SUBJECTS: Joi.string().required(),
  // Phase 3: JWT Auth (D-11)
  JWT_SECRET: Joi.string().min(32).required(),
  JWT_PUBLIC_KEY: Joi.string().optional(),
  JWKS_URI: Joi.string().uri().optional(),
  JWT_ISSUER: Joi.string().optional(),
  JWT_AUDIENCE: Joi.string().optional(),
  DATABASE_URL: Joi.string()
    .pattern(/^postgres(ql)?:\/\//i)
    .required(),
  TRUST_KNOWN_THRESHOLD: Joi.number().default(3),
  TRUST_DECAY_HALFLIFE_MS: Joi.number().default(604800000),
  TRUST_ANOMALY_WARMUP_N: Joi.number().default(20),
  TRUST_FREQUENCY_WINDOW_MS: Joi.number().default(60000),
  TRUST_FREQUENCY_NORMAL_MAX: Joi.number().default(30),
  // Phase 5: Hashcash PoW (D-17)
  HASHCASH_HMAC_SECRET: Joi.string().min(32).required(),
  HASHCASH_CHALLENGE_TTL_MS: Joi.number().default(120000),
  HASHCASH_USED_NONCE_CAPACITY: Joi.number().default(10000),
  HASHCASH_TRIGGER_THRESHOLD: Joi.number().default(0.7),
  HASHCASH_DIFFICULTY_MIN: Joi.number().default(18),
  HASHCASH_DIFFICULTY_MAX: Joi.number().default(22),
});

async function createModuleWithEnv() {
  const module = await Test.createTestingModule({
    imports: [
      ConfigModule.forRoot({
        isGlobal: true,
        ignoreEnvFile: true,
        validationSchema: joiSchema,
        validationOptions: { abortEarly: false },
      }),
    ],
    providers: [AppConfigService],
  }).compile();
  return module.get(AppConfigService);
}

describe('AppConfigService', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    // Restore original env
    for (const key of Object.keys(process.env)) {
      if (!(key in originalEnv)) {
        delete process.env[key];
      }
    }
    Object.assign(process.env, originalEnv);
  });

  describe('validation — fail-fast (CONF-01)', () => {
    it('throws when MTLS_CA_CERT_PATH is missing', async () => {
      setRequiredEnv();
      delete process.env.MTLS_CA_CERT_PATH;

      await expect(createModuleWithEnv()).rejects.toThrow();
    });

    it('throws listing ALL missing vars at once (not one at a time)', async () => {
      // Remove all 4 required mTLS vars
      delete process.env.MTLS_CA_CERT_PATH;
      delete process.env.MTLS_CLIENT_CERT_PATH;
      delete process.env.MTLS_CLIENT_KEY_PATH;
      delete process.env.MTLS_ALLOWED_SUBJECTS;

      let errorMessage = '';
      try {
        await createModuleWithEnv();
      } catch (err: unknown) {
        errorMessage = err instanceof Error ? err.message : String(err);
      }

      expect(errorMessage).toContain('MTLS_CA_CERT_PATH');
      expect(errorMessage).toContain('MTLS_CLIENT_CERT_PATH');
      expect(errorMessage).toContain('MTLS_CLIENT_KEY_PATH');
      expect(errorMessage).toContain('MTLS_ALLOWED_SUBJECTS');
    });
  });

  describe('typed getters (CONF-02)', () => {
    it('port getter returns PORT from env', async () => {
      setRequiredEnv();
      process.env.PORT = '4000';

      const service = await createModuleWithEnv();
      expect(service.port).toBe(4000);
    });

    it('port getter returns 3000 when PORT not set', async () => {
      setRequiredEnv();
      delete process.env.PORT;

      const service = await createModuleWithEnv();
      expect(service.port).toBe(3000);
    });

    it('corsOrigin getter returns CORS_ORIGIN from env', async () => {
      setRequiredEnv();
      process.env.CORS_ORIGIN = 'https://example.com';

      const service = await createModuleWithEnv();
      expect(service.corsOrigin).toBe('https://example.com');
    });

    it("corsOrigin defaults to '*' when not set", async () => {
      setRequiredEnv();
      delete process.env.CORS_ORIGIN;

      const service = await createModuleWithEnv();
      expect(service.corsOrigin).toBe('*');
    });

    it('rateLimitWindowMs getter returns number from env', async () => {
      setRequiredEnv();
      process.env.RATE_LIMIT_WINDOW_MS = '30000';

      const service = await createModuleWithEnv();
      expect(service.rateLimitWindowMs).toBe(30000);
    });

    it('rateLimitMax getter returns number from env', async () => {
      setRequiredEnv();
      process.env.RATE_LIMIT_MAX = '50';

      const service = await createModuleWithEnv();
      expect(service.rateLimitMax).toBe(50);
    });

    it('mtlsCaCertPath getter returns MTLS_CA_CERT_PATH', async () => {
      setRequiredEnv();

      const service = await createModuleWithEnv();
      expect(service.mtlsCaCertPath).toBe('/tmp/ca.pem');
    });

    it('mtlsClientCertPath getter returns MTLS_CLIENT_CERT_PATH', async () => {
      setRequiredEnv();

      const service = await createModuleWithEnv();
      expect(service.mtlsClientCertPath).toBe('/tmp/client.pem');
    });

    it('mtlsClientKeyPath getter returns MTLS_CLIENT_KEY_PATH', async () => {
      setRequiredEnv();

      const service = await createModuleWithEnv();
      expect(service.mtlsClientKeyPath).toBe('/tmp/client-key.pem');
    });

    it('mtlsAllowedSubjects getter returns parsed array', async () => {
      setRequiredEnv();
      process.env.MTLS_ALLOWED_SUBJECTS = 'cn1,cn2,cn3';

      const service = await createModuleWithEnv();
      expect(service.mtlsAllowedSubjects).toEqual(['cn1', 'cn2', 'cn3']);
    });
  });

  describe('Phase 4 trust + database config (D-21)', () => {
    it('databaseUrl returns DATABASE_URL', async () => {
      setRequiredEnv();
      const service = await createModuleWithEnv();
      expect(service.databaseUrl).toBe(
        'postgresql://ztgateway:ztgateway@localhost:5432/ztgateway',
      );
    });

    it('trust getters return defaults when unset', async () => {
      setRequiredEnv();
      delete process.env.TRUST_KNOWN_THRESHOLD;
      delete process.env.TRUST_DECAY_HALFLIFE_MS;
      delete process.env.TRUST_ANOMALY_WARMUP_N;
      delete process.env.TRUST_FREQUENCY_WINDOW_MS;
      delete process.env.TRUST_FREQUENCY_NORMAL_MAX;

      const service = await createModuleWithEnv();
      expect(service.trustKnownThreshold).toBe(3);
      expect(service.trustDecayHalfLifeMs).toBe(604800000);
      expect(service.trustAnomalyWarmupN).toBe(20);
      expect(service.trustFrequencyWindowMs).toBe(60000);
      expect(service.trustFrequencyNormalMax).toBe(30);
    });

    it('throws when DATABASE_URL is missing', async () => {
      setRequiredEnv();
      delete process.env.DATABASE_URL;

      await expect(createModuleWithEnv()).rejects.toThrow();
    });
  });

  describe('JWT config group (CONF-03 Phase 3, D-11)', () => {
    it('throws when JWT_SECRET is missing', async () => {
      setRequiredEnv();
      delete process.env.JWT_SECRET;

      await expect(createModuleWithEnv()).rejects.toThrow();
    });

    it('throws when JWT_SECRET is shorter than 32 chars', async () => {
      setRequiredEnv();
      process.env.JWT_SECRET = 'too-short';

      await expect(createModuleWithEnv()).rejects.toThrow();
    });

    it('jwtSecret getter returns JWT_SECRET value', async () => {
      setRequiredEnv();
      const service = await createModuleWithEnv();
      expect(service.jwtSecret).toBe('test-secret-that-is-at-least-32-chars-long!');
    });

    it('jwtPublicKey returns undefined when JWT_PUBLIC_KEY not set', async () => {
      setRequiredEnv();
      const service = await createModuleWithEnv();
      expect(service.jwtPublicKey).toBeUndefined();
    });

    it('jwtPublicKey returns value when JWT_PUBLIC_KEY is set', async () => {
      setRequiredEnv();
      process.env.JWT_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----';
      const service = await createModuleWithEnv();
      expect(service.jwtPublicKey).toBe('-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----');
    });

    it('jwksUri returns undefined when JWKS_URI not set', async () => {
      setRequiredEnv();
      const service = await createModuleWithEnv();
      expect(service.jwksUri).toBeUndefined();
    });

    it('jwksUri returns value when JWKS_URI is set', async () => {
      setRequiredEnv();
      process.env.JWKS_URI = 'https://idp.example.com/.well-known/jwks.json';
      const service = await createModuleWithEnv();
      expect(service.jwksUri).toBe('https://idp.example.com/.well-known/jwks.json');
    });

    it('jwtIssuer returns undefined when JWT_ISSUER not set', async () => {
      setRequiredEnv();
      const service = await createModuleWithEnv();
      expect(service.jwtIssuer).toBeUndefined();
    });

    it('jwtAudience returns undefined when JWT_AUDIENCE not set', async () => {
      setRequiredEnv();
      const service = await createModuleWithEnv();
      expect(service.jwtAudience).toBeUndefined();
    });
  });

  describe('HASHCASH config (Phase 5)', () => {
    it('Joi rejects startup when HASHCASH_HMAC_SECRET is missing', async () => {
      setRequiredEnv();
      delete process.env.HASHCASH_HMAC_SECRET;

      await expect(createModuleWithEnv()).rejects.toThrow();
    });

    it('Joi rejects HASHCASH_HMAC_SECRET shorter than 32 chars', async () => {
      setRequiredEnv();
      process.env.HASHCASH_HMAC_SECRET = 'too-short';

      await expect(createModuleWithEnv()).rejects.toThrow();
    });

    it('hashcashHmacSecret getter returns HASHCASH_HMAC_SECRET value', async () => {
      setRequiredEnv();
      const service = await createModuleWithEnv();
      expect(service.hashcashHmacSecret).toBe(
        'hashcash-secret-that-is-at-least-32-chars-long!',
      );
    });

    it('hashcashChallengeTtlMs defaults to 120000 when env unset', async () => {
      setRequiredEnv();
      delete process.env.HASHCASH_CHALLENGE_TTL_MS;
      const service = await createModuleWithEnv();
      expect(service.hashcashChallengeTtlMs).toBe(120000);
    });

    it('hashcashUsedNonceCapacity defaults to 10000', async () => {
      setRequiredEnv();
      delete process.env.HASHCASH_USED_NONCE_CAPACITY;
      const service = await createModuleWithEnv();
      expect(service.hashcashUsedNonceCapacity).toBe(10000);
    });

    it('hashcashTriggerThreshold defaults to 0.7', async () => {
      setRequiredEnv();
      delete process.env.HASHCASH_TRIGGER_THRESHOLD;
      const service = await createModuleWithEnv();
      expect(service.hashcashTriggerThreshold).toBe(0.7);
    });

    it('hashcashDifficultyMin defaults to 18', async () => {
      setRequiredEnv();
      delete process.env.HASHCASH_DIFFICULTY_MIN;
      const service = await createModuleWithEnv();
      expect(service.hashcashDifficultyMin).toBe(18);
    });

    it('hashcashDifficultyMax defaults to 22', async () => {
      setRequiredEnv();
      delete process.env.HASHCASH_DIFFICULTY_MAX;
      const service = await createModuleWithEnv();
      expect(service.hashcashDifficultyMax).toBe(22);
    });

    it('explicit HASHCASH_DIFFICULTY_MIN=4 and MAX=4 override defaults (e2e knob)', async () => {
      setRequiredEnv();
      process.env.HASHCASH_DIFFICULTY_MIN = '4';
      process.env.HASHCASH_DIFFICULTY_MAX = '4';
      const service = await createModuleWithEnv();
      expect(service.hashcashDifficultyMin).toBe(4);
      expect(service.hashcashDifficultyMax).toBe(4);
    });

    it('hashcashHmacSecret is distinct from jwtSecret (D-05 separation)', async () => {
      setRequiredEnv();
      process.env.JWT_SECRET = 'jwt-secret-that-is-at-least-32-chars-long-AAAA';
      process.env.HASHCASH_HMAC_SECRET =
        'hashcash-secret-that-is-at-least-32-chars-long-BBBB';
      const service = await createModuleWithEnv();
      expect(service.hashcashHmacSecret).not.toBe(service.jwtSecret);
    });
  });

  describe('Phase 6: POLICY_*/THREAT_* schema + cross-field validator (D-23)', () => {
    // Bootstrap the REAL ConfigAppModule so we exercise the production schema
    // (including .custom() cross-field validator) end-to-end.
    async function createRealModule() {
      const module = await Test.createTestingModule({
        imports: [ConfigAppModule],
      }).compile();
      return module.get(AppConfigService);
    }

    it('accepts bootstrap with all defaults (no Phase 6 env vars set)', async () => {
      setRequiredEnv();
      // Defaults must be schema-valid (Elevated/Critical strictly tighter than Normal)
      await expect(createRealModule()).resolves.toBeDefined();
    });

    it('Test 2 — rejects bootstrap when Elevated challenge >= Normal challenge', async () => {
      setRequiredEnv();
      process.env.POLICY_ELEVATED_CHALLENGE_THRESHOLD = '0.5'; // not strictly < 0.5

      let errMsg = '';
      try {
        await createRealModule();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain(
        'POLICY_ELEVATED_CHALLENGE_THRESHOLD must be < POLICY_CHALLENGE_THRESHOLD',
      );
    });

    it('Test 3 — rejects when Critical challenge >= Elevated challenge', async () => {
      setRequiredEnv();
      process.env.POLICY_ELEVATED_CHALLENGE_THRESHOLD = '0.3';
      process.env.POLICY_CRITICAL_CHALLENGE_THRESHOLD = '0.4'; // not < 0.3

      let errMsg = '';
      try {
        await createRealModule();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain(
        'POLICY_CRITICAL_CHALLENGE_THRESHOLD must be < POLICY_ELEVATED_CHALLENGE_THRESHOLD',
      );
    });

    it('Test 4 — rejects when Elevated denies >= Critical denies (count direction)', async () => {
      setRequiredEnv();
      process.env.THREAT_ELEVATED_DENIES = '50';
      process.env.THREAT_CRITICAL_DENIES = '20';

      let errMsg = '';
      try {
        await createRealModule();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain(
        'THREAT_ELEVATED_DENIES must be < THREAT_CRITICAL_DENIES',
      );
    });

    it('Test 5 — rejects POLICY_CHALLENGE_THRESHOLD outside [0,1]', async () => {
      setRequiredEnv();
      process.env.POLICY_CHALLENGE_THRESHOLD = '1.5';

      await expect(createRealModule()).rejects.toThrow();
    });

    it('Test 6 — rejects THREAT_WINDOW_MS below 1000', async () => {
      setRequiredEnv();
      process.env.THREAT_WINDOW_MS = '500';

      await expect(createRealModule()).rejects.toThrow();
    });

    it('rejects when Elevated deny threshold not < Normal deny threshold', async () => {
      setRequiredEnv();
      process.env.POLICY_ELEVATED_DENY_THRESHOLD = '0.8'; // not < 0.8

      let errMsg = '';
      try {
        await createRealModule();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain(
        'POLICY_ELEVATED_DENY_THRESHOLD must be < POLICY_DENY_THRESHOLD',
      );
    });

    it('rejects when Critical deny threshold not < Elevated deny threshold', async () => {
      setRequiredEnv();
      process.env.POLICY_ELEVATED_DENY_THRESHOLD = '0.6';
      process.env.POLICY_CRITICAL_DENY_THRESHOLD = '0.7'; // not < 0.6

      let errMsg = '';
      try {
        await createRealModule();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain(
        'POLICY_CRITICAL_DENY_THRESHOLD must be < POLICY_ELEVATED_DENY_THRESHOLD',
      );
    });

    it('rejects when Elevated invalid_tokens >= Critical invalid_tokens', async () => {
      setRequiredEnv();
      process.env.THREAT_ELEVATED_INVALID_TOKENS = '80';
      process.env.THREAT_CRITICAL_INVALID_TOKENS = '30';

      let errMsg = '';
      try {
        await createRealModule();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain(
        'THREAT_ELEVATED_INVALID_TOKENS must be < THREAT_CRITICAL_INVALID_TOKENS',
      );
    });

    it('rejects when Elevated honeypot >= Critical honeypot', async () => {
      setRequiredEnv();
      process.env.THREAT_ELEVATED_HONEYPOT = '15';
      process.env.THREAT_CRITICAL_HONEYPOT = '5';

      let errMsg = '';
      try {
        await createRealModule();
      } catch (err) {
        errMsg = err instanceof Error ? err.message : String(err);
      }
      expect(errMsg).toContain(
        'THREAT_ELEVATED_HONEYPOT must be < THREAT_CRITICAL_HONEYPOT',
      );
    });
  });
});
