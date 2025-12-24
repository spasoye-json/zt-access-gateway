import { NestFactory } from '@nestjs/core';
import { PermissionsModule } from './permissions.module';
import * as https from 'https';
import * as fs from 'fs';
import { GatewayOnlyGuard } from 'microservices/gateway-only.guard';

async function bootstrap() {
  // Create HTTPS server options with certificate
  // Try different possible paths for the certificates
  let keyPath = './certs/permissions-service.key';
  let certPath = './certs/permissions-service.crt';
  let caPath = './certs/ca.crt';

  // Check if files exist at the default path, otherwise try alternative paths
  if (!fs.existsSync(keyPath)) {
    keyPath = '/app/certs/permissions-service.key';
  }
  if (!fs.existsSync(certPath)) {
    certPath = '/app/certs/permissions-service.crt';
  }
  if (!fs.existsSync(caPath)) {
    caPath = '/app/certs/ca.crt';
  }

  const httpsOptions: https.ServerOptions = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
    ca: fs.readFileSync(caPath),
    requestCert: true,
    rejectUnauthorized: true,
  };

  const app = await NestFactory.create(PermissionsModule, {
    httpsOptions,
  });

  app.useGlobalGuards(new GatewayOnlyGuard());
  
  await app.listen(3003, '0.0.0.0');
  console.log('Permissions service is running on https://0.0.0.0:3003');
}
bootstrap();
