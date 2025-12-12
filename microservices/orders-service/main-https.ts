import { NestFactory } from '@nestjs/core';
import { OrdersModule } from './orders.module';
import * as https from 'https';
import * as fs from 'fs';

async function bootstrap() {
  // Create HTTPS server options with certificate
  // Try different possible paths for the certificates
  let keyPath = './certs/orders-service.key';
  let certPath = './certs/orders-service.crt';

  // Check if files exist at the default path, otherwise try alternative paths
  if (!fs.existsSync(keyPath)) {
    keyPath = '/app/certs/orders-service.key';
  }
  if (!fs.existsSync(certPath)) {
    certPath = '/app/certs/orders-service.crt';
  }

  const httpsOptions = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
  };

  const app = await NestFactory.create(OrdersModule, {
    httpsOptions,
  });

  await app.listen(3002); // Using HTTPS on port 3002
  console.log('Orders service is running on https://localhost:3002');
}
bootstrap();