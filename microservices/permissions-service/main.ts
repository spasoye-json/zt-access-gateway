import { NestFactory } from '@nestjs/core';
import { PermissionsModule } from './permissions.module';
import * as https from 'https';
import * as fs from 'fs';

async function bootstrap() {
  // Create HTTPS server options with certificate
  // Try different possible paths for the certificates
  let keyPath = './certs/permissions-service.key';
  let certPath = './certs/permissions-service.crt';

  // Check if files exist at the default path, otherwise try alternative paths
  if (!fs.existsSync(keyPath)) {
    keyPath = '../certs/permissions-service.key';
  }
  if (!fs.existsSync(certPath)) {
    certPath = '../certs/permissions-service.crt';
  }

  // If certificates don't exist, run without HTTPS for development
  let httpsOptions = {};
  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    httpsOptions = {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    };
  } else {
    console.warn('Certificates not found, running permissions service without HTTPS');
  }

  const app = await NestFactory.create(PermissionsModule, {
    httpsOptions: Object.keys(httpsOptions).length > 0 ? httpsOptions : undefined,
  });

  await app.listen(3003); // Using HTTPS on port 3003 if certificates exist, otherwise plain HTTP
  console.log('Permissions service is running on https://localhost:3003');
}
bootstrap();