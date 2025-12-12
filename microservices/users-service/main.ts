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
    keyPath = '../certs/users-service.key';
  }
  if (!fs.existsSync(certPath)) {
    certPath = '../certs/users-service.crt';
  }

  // If certificates don't exist, run without HTTPS for development
  let httpsOptions = {};
  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    httpsOptions = {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    };
  } else {
    console.warn('Certificates not found, running users service without HTTPS');
  }

  const app = await NestFactory.create(UsersModule, {
    httpsOptions: Object.keys(httpsOptions).length > 0 ? httpsOptions : undefined,
  });

  await app.listen(3001); // Using HTTPS on port 3001 if certificates exist, otherwise plain HTTP
  console.log('Users service is running on https://localhost:3001');
}
bootstrap();