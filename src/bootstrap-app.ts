import { INestApplication, ValidationPipe } from '@nestjs/common';
import { ConfigService as NestConfigService } from '@nestjs/config';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { HttpExceptionFilter } from './shared/filters/http-exception.filter';

const parseOrigins = (origins?: string | null): true | string[] => {
  if (!origins) return true;
  const list = origins
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
  return list.length ? list : true;
};

const shouldEnforceStrictConfig = (configService: NestConfigService): boolean => {
  const strict = configService.get<string>('STRICT_CONFIG');
  if (strict === 'true') {
    return true;
  }

  const nodeEnv = (configService.get<string>('NODE_ENV') || '').toLowerCase();
  return nodeEnv === 'production';
};

const requireConfig = (configService: NestConfigService, key: string): string => {
  const value = configService.get<string>(key);
  if (!value) {
    throw new Error(`Missing required configuration: ${key}`);
  }
  return value;
};

export const validateCriticalConfig = (configService: NestConfigService) => {
  if (!shouldEnforceStrictConfig(configService)) {
    return;
  }

  const algorithm = (configService.get<string>('JWT_ALGORITHM') || 'HS256')
    .toUpperCase()
    .trim();

  if (algorithm.startsWith('HS')) {
    requireConfig(configService, 'JWT_SECRET');
  } else if (algorithm.startsWith('RS') || algorithm.startsWith('ES')) {
    requireConfig(configService, 'JWT_JWKS_URI');
  } else {
    throw new Error(`Unsupported JWT_ALGORITHM: ${algorithm}`);
  }

  requireConfig(configService, 'MTLS_CA_CERT_PATH');
  requireConfig(configService, 'MTLS_CERT_PATH');
  requireConfig(configService, 'MTLS_KEY_PATH');

  const registry = requireConfig(configService, 'SERVICE_REGISTRY');
  try {
    JSON.parse(registry);
  } catch (error) {
    throw new Error('SERVICE_REGISTRY must be valid JSON');
  }
};

export const configureApp = (
  app: INestApplication,
  configService: NestConfigService,
) => {
  app.use(helmet());

  // Basic request correlation for logs/responses
  app.use((req, res, next) => {
    const existingId = req.headers['x-request-id'] as string | undefined;
    const requestId =
      existingId ||
      `req-${Date.now().toString(36)}-${Math.random()
        .toString(36)
        .slice(2, 8)}`;
    req.headers['x-request-id'] = requestId;
    res.setHeader('x-request-id', requestId);
    next();
  });

  app.enableCors({
    origin: parseOrigins(configService.get<string>('CORS_ORIGINS')),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'authorization',
      'content-type',
      'x-device-id',
      'x-forwarded-for',
      'x-request-id',
    ],
  });

  app.use(
    rateLimit({
      windowMs: Number(configService.get('RATE_LIMIT_WINDOW_MS') ?? 60_000),
      max: Number(configService.get('RATE_LIMIT_MAX') ?? 100),
      standardHeaders: true,
      legacyHeaders: false,
      message: {
        error: 'Too Many Requests',
        message: 'Rate limit exceeded. Try again later.',
      },
    }),
  );

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
      transformOptions: { enableImplicitConversion: true },
    }),
  );

  app.useGlobalFilters(new HttpExceptionFilter());

  const server = app.getHttpServer();
  console.log(server._events?.request?._router?.stack?.map((l) => l.route && l.route.path).filter(Boolean));
};
