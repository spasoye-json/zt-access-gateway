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
      }),
      // List ALL missing vars at once, not one at a time (D-03)
      validationOptions: { abortEarly: false },
    }),
  ],
  providers: [AppConfigService],
  exports: [AppConfigService],
})
export class ConfigAppModule {}
