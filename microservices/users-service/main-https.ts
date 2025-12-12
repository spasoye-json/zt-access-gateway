import { NestFactory } from '@nestjs/core';
import { UsersModule } from './users.module';
import * as https from 'https';
import * as fs from 'fs';

async function bootstrap() {
  // Create HTTPS server options with certificate
  // Try different possible paths for the certificates
  let keyPath = './certs/users-service.key';
  let certPath = './certs/users-service.crt';

  // Check if files exist at the default path, otherwise try alternative paths
  if (!fs.existsSync(keyPath)) {
    keyPath = '/app/certs/users-service.key';
  }
  if (!fs.existsSync(certPath)) {
    certPath = '/app/certs/users-service.crt';
  }

  const httpsOptions = {
    key: fs.readFileSync(keyPath),
    cert: fs.readFileSync(certPath),
  };

  const app = await NestFactory.create(UsersModule, {
    httpsOptions,
  });

  await app.listen(3001); // Using HTTPS on port 3001
  console.log('Users service is running on https://localhost:3001');
}
bootstrap();