import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import * as Joi from 'joi';
import { AppConfigService } from './config.service';

/**
 * Production Joi validation schema with Phase 6 D-23 cross-field validator.
 *
 * Exported so tests can re-validate per-test with custom env (without relying
 * on ConfigModule.forRoot's one-shot evaluation at module load time — see
 * Phase 6 spec block in __tests__/config.service.spec.ts).
 */
export const validationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  PORT: Joi.number().default(3000),
  CORS_ORIGIN: Joi.string().default('*'),
  RATE_LIMIT_WINDOW_MS: Joi.number().default(60000),
  RATE_LIMIT_MAX: Joi.number().default(100),
  // mTLS paths are required — fail-fast on startup (CONF-01, D-03)
  MTLS_CA_CERT_PATH: Joi.string().required(),
  MTLS_CLIENT_CERT_PATH: Joi.string().required(),
  MTLS_CLIENT_KEY_PATH: Joi.string().required(),
  MTLS_ALLOWED_SUBJECTS: Joi.string().required(),
  // Phase 2: JA4H + Honeypot (D-03)
  BLACKLIST_TTL_MS: Joi.number().default(3600000),
  HONEYPOT_ROUTES: Joi.string().allow('').optional().default(''),
  // Phase 3: JWT Auth (D-11)
  JWT_SECRET: Joi.string().min(32).required(),
  JWT_PUBLIC_KEY: Joi.string().optional(),
  JWKS_URI: Joi.string().uri().optional(),
  JWT_ISSUER: Joi.string().optional(),
  JWT_AUDIENCE: Joi.string().optional(),
  // Phase 4: Trust + Postgres (D-21)
  DATABASE_URL: Joi.string()
    .pattern(/^postgres(ql)?:\/\//i)
    .required()
    .messages({
      'string.pattern.base':
        'DATABASE_URL must start with postgres:// or postgresql://',
    }),
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
  // Phase 6: Policy + Threat Escalation (D-23)
  POLICY_MODEL_PATH: Joi.string().default('policy/model.conf'),
  POLICY_CSV_PATH: Joi.string().default('policy/policy.csv'),
  POLICY_CHALLENGE_THRESHOLD: Joi.number().min(0).max(1).default(0.5),
  POLICY_DENY_THRESHOLD: Joi.number().min(0).max(1).default(0.8),
  POLICY_ELEVATED_CHALLENGE_THRESHOLD: Joi.number().min(0).max(1).default(0.3),
  POLICY_ELEVATED_DENY_THRESHOLD: Joi.number().min(0).max(1).default(0.6),
  POLICY_CRITICAL_CHALLENGE_THRESHOLD: Joi.number().min(0).max(1).default(0.2),
  POLICY_CRITICAL_DENY_THRESHOLD: Joi.number().min(0).max(1).default(0.4),
  THREAT_WINDOW_MS: Joi.number().integer().min(1000).default(300000),
  THREAT_WINDOW_MAX_EVENTS: Joi.number().integer().min(1).default(10000),
  THREAT_ELEVATED_DENIES: Joi.number().integer().min(1).default(20),
  THREAT_CRITICAL_DENIES: Joi.number().integer().min(1).default(50),
  THREAT_ELEVATED_INVALID_TOKENS: Joi.number().integer().min(1).default(30),
  THREAT_CRITICAL_INVALID_TOKENS: Joi.number().integer().min(1).default(80),
  THREAT_ELEVATED_HONEYPOT: Joi.number().integer().min(1).default(5),
  THREAT_CRITICAL_HONEYPOT: Joi.number().integer().min(1).default(15),
  THREAT_ELEVATED_MFA_RATE_LIMITED: Joi.number().integer().min(1).default(5),
  THREAT_CRITICAL_MFA_RATE_LIMITED: Joi.number().integer().min(1).default(15),
  THREAT_COOLDOWN_MS: Joi.number().integer().min(1000).default(600000),
  // Phase 7: MFA Challenge (D-09, D-15, D-03, D-17)
  MFA_JWT_SECRET: Joi.string().min(32).required(),
  MFA_TOTP_ENCRYPTION_KEY: Joi.string().min(44).required(),
  MFA_CHALLENGE_TTL_MS: Joi.number().integer().min(1).default(300000),
  MFA_TOKEN_TTL_MS: Joi.number().integer().min(1).default(600000),
  MFA_RATE_LIMIT_MAX: Joi.number().integer().min(1).default(5),
  MFA_RATE_LIMIT_WINDOW_MS: Joi.number().integer().min(1).default(60000),
  // Phase 11: MFA Enrollment (D-11)
  MFA_ISSUER_NAME: Joi.string().default('ZT-Gateway'),
  MFA_ENROLL_PENDING_TTL_MS: Joi.number().integer().min(1).default(600000),
  // Phase 8: Proxy + BOPLA (D-01, D-12)
  PROXY_SERVICE_REGISTRY: Joi.string().required(),
  PROXY_CB_VOLUME_THRESHOLD: Joi.number().integer().min(1).default(5),
  PROXY_CB_ERROR_THRESHOLD: Joi.number().min(1).max(100).default(50),
  PROXY_CB_RESET_TIMEOUT: Joi.number().integer().min(1000).default(10000),
  PROXY_MAX_RETRIES: Joi.number().integer().min(0).max(10).default(3),
  BOPLA_POLICY_PATH: Joi.string().default('policy/field-policy.json'),
  // Phase 9: Audit WAL (D-06)
  AUDIT_WAL_BASE_DELAY_MS: Joi.number().integer().min(1).default(50),
  AUDIT_WAL_MAX_RETRIES: Joi.number().integer().min(1).max(10).default(3),
}).custom((cfg, helpers) => {
  // D-23 cross-field validator: Elevated/Critical MUST be strictly tighter than Normal.
  // Tighter at higher level (challenge threshold)
  if (
    !(cfg.POLICY_ELEVATED_CHALLENGE_THRESHOLD < cfg.POLICY_CHALLENGE_THRESHOLD)
  )
    return helpers.message({
      custom:
        'POLICY_ELEVATED_CHALLENGE_THRESHOLD must be < POLICY_CHALLENGE_THRESHOLD',
    });
  if (
    !(
      cfg.POLICY_CRITICAL_CHALLENGE_THRESHOLD <
      cfg.POLICY_ELEVATED_CHALLENGE_THRESHOLD
    )
  )
    return helpers.message({
      custom:
        'POLICY_CRITICAL_CHALLENGE_THRESHOLD must be < POLICY_ELEVATED_CHALLENGE_THRESHOLD',
    });
  // Tighter at higher level (deny threshold)
  if (!(cfg.POLICY_ELEVATED_DENY_THRESHOLD < cfg.POLICY_DENY_THRESHOLD))
    return helpers.message({
      custom: 'POLICY_ELEVATED_DENY_THRESHOLD must be < POLICY_DENY_THRESHOLD',
    });
  if (
    !(cfg.POLICY_CRITICAL_DENY_THRESHOLD < cfg.POLICY_ELEVATED_DENY_THRESHOLD)
  )
    return helpers.message({
      custom:
        'POLICY_CRITICAL_DENY_THRESHOLD must be < POLICY_ELEVATED_DENY_THRESHOLD',
    });
  // Counts: Elevated < Critical per signal type
  if (!(cfg.THREAT_ELEVATED_DENIES < cfg.THREAT_CRITICAL_DENIES))
    return helpers.message({
      custom: 'THREAT_ELEVATED_DENIES must be < THREAT_CRITICAL_DENIES',
    });
  if (
    !(cfg.THREAT_ELEVATED_INVALID_TOKENS < cfg.THREAT_CRITICAL_INVALID_TOKENS)
  )
    return helpers.message({
      custom:
        'THREAT_ELEVATED_INVALID_TOKENS must be < THREAT_CRITICAL_INVALID_TOKENS',
    });
  if (!(cfg.THREAT_ELEVATED_HONEYPOT < cfg.THREAT_CRITICAL_HONEYPOT))
    return helpers.message({
      custom: 'THREAT_ELEVATED_HONEYPOT must be < THREAT_CRITICAL_HONEYPOT',
    });
  if (
    !(
      cfg.THREAT_ELEVATED_MFA_RATE_LIMITED <
      cfg.THREAT_CRITICAL_MFA_RATE_LIMITED
    )
  )
    return helpers.message({
      custom:
        'THREAT_ELEVATED_MFA_RATE_LIMITED must be < THREAT_CRITICAL_MFA_RATE_LIMITED',
    });
  // D-03 cross-field: challenge TTL must be shorter than token TTL
  if (!(cfg.MFA_CHALLENGE_TTL_MS < cfg.MFA_TOKEN_TTL_MS))
    return helpers.message({
      custom: 'MFA_CHALLENGE_TTL_MS must be < MFA_TOKEN_TTL_MS',
    });
  return cfg;
});

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema,
      // List ALL missing vars at once, not one at a time (D-03)
      validationOptions: { abortEarly: false },
    }),
  ],
  providers: [AppConfigService],
  exports: [AppConfigService],
})
export class ConfigAppModule {}
