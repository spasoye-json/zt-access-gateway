import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { ConfigService as NestConfigService } from '@nestjs/config';
import { AppModule } from './app.module';
import { configureApp, validateCriticalConfig } from './bootstrap-app';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bufferLogs: true });
  const logger = new Logger('Bootstrap');
  const configService = app.get(NestConfigService);

  validateCriticalConfig(configService);
  configureApp(app, configService);

  const port = configService.get<number>('PORT') || 3000;

  await app.listen(port);

  logger.log(`Zero-Trust Access Gateway is running on port ${port}`);
}
bootstrap();
