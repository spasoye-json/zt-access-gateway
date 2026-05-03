import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { Client } from 'pg';
import * as fs from 'fs';
import * as path from 'path';
import { AppModule } from './app.module';
import { AppConfigService } from './config/config.service';
import { HttpExceptionFilter } from './shared/http-exception.filter';

async function runMigrations(databaseUrl: string): Promise<void> {
  const client = new Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    const dir = path.join(__dirname, '..', 'sql', 'migrations');
    const files = fs.readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
    for (const file of files) {
      await client.query(fs.readFileSync(path.join(dir, file), 'utf8'));
    }
  } finally {
    await client.end();
  }
}

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const config = app.get(AppConfigService);

  await runMigrations(config.databaseUrl);

  // 1. Security headers — must be first to apply to every response (T-01-10, RESEARCH.md Pattern 6)
  app.use(helmet());

  // 2. CORS — before rate limiting so OPTIONS preflight is not rate-limited (D-06, BOOT-04)
  app.enableCors({ origin: config.corsOrigin });

  // 3. Rate limiting — IP-based global throttler, returns 429 when exceeded (T-01-11, D-08, BOOT-02)
  app.use(
    rateLimit({
      windowMs: config.rateLimitWindowMs,
      max: config.rateLimitMax,
      standardHeaders: true,
      legacyHeaders: false,
    }),
  );

  // 4. Global exception filter — structured JSON errors, no stack traces in responses (T-01-13, SHRD-06)
  app.useGlobalFilters(new HttpExceptionFilter());

  // 5. Global validation pipe — strips unknown fields, transforms types for future DTOs
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Note: JA4H fingerprinting middleware is registered in AppModule.configure() via MiddlewareConsumer
  // (Phase 2) — NestJS DI-aware middleware runs after the global Express middleware above.
  await app.listen(config.port);
}
bootstrap();
