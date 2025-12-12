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
    keyPath = '/app/certs/permissions-service.key';
  }
  if (!fs.existsSync(certPath)) {
    certPath = '/app/certs/permissions-service.crt';
  }

  const httpsOptions = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
  };

  const app = await NestFactory.create(PermissionsModule, {
    httpsOptions,
  });

  await app.listen(3003); // Using HTTPS on port 3003
  console.log('Permissions service is running on https://localhost:3003');
}
bootstrap();