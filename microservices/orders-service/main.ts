import { NestFactory } from '@nestjs/core';
import { OrdersModule } from './orders.module';
import * as https from 'https';
import * as fs from 'fs';
import { GatewayOnlyGuard } from 'microservices/gateway-only.guard';

async function bootstrap() {
  // Create HTTPS server options with certificate
  // Try different possible paths for the certificates
  let keyPath = './certs/orders-service.key';
  let certPath = './certs/orders-service.crt';

  // Check if files exist at the default path, otherwise try alternative paths
  if (!fs.existsSync(keyPath)) {
    keyPath = '../certs/orders-service.key';
  }
  if (!fs.existsSync(certPath)) {
    certPath = '../certs/orders-service.crt';
  }

  // If certificates don't exist, run without HTTPS for development
  let httpsOptions = {};
  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    httpsOptions = {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    };
  } else {
    console.warn('Certificates not found, running orders service without HTTPS');
  }

  const app = await NestFactory.create(OrdersModule, {
    httpsOptions: Object.keys(httpsOptions).length > 0 ? httpsOptions : undefined,
  });

  app.useGlobalGuards(new GatewayOnlyGuard());

  await app.listen(3002, '0.0.0.0');
  console.log('Orders service is running on https://0.0.0.0:3002');
}
bootstrap();