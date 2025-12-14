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
