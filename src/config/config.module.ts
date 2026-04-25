import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import * as Joi from 'joi';
import { AppConfigService } from './config.service';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      // Phase 1 vars only — no forward declarations (D-01, D-02)
      validationSchema: Joi.object({
        NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
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
      }),
      // List ALL missing vars at once, not one at a time (D-03)
      validationOptions: { abortEarly: false },
    }),
  ],
  providers: [AppConfigService],
  exports: [AppConfigService],
})
export class ConfigAppModule {}
