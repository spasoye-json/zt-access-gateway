import { NestFactory } from '@nestjs/core';
import { UsersModule } from './users.module';
import * as https from 'https';
import * as fs from 'fs';
import { GatewayOnlyGuard } from 'microservices/gateway-only.guard';

async function bootstrap() {
  const allowInsecureHttp = process.env.ALLOW_INSECURE_MICROSERVICE_HTTP === 'true';

  // Create HTTPS server options with certificate
  // Try different possible paths for the certificates
  let keyPath = './certs/users-service.key';
  let certPath = './certs/users-service.crt';
  let caPath = './certs/ca.crt';

  // Check if files exist at the default path, otherwise try alternative paths
  if (!fs.existsSync(keyPath)) {
    keyPath = '../certs/users-service.key';
  }
  if (!fs.existsSync(certPath)) {
    certPath = '../certs/users-service.crt';
  }
  if (!fs.existsSync(caPath)) {
    caPath = '../certs/ca.crt';
  }

  // If certificates don't exist, run without HTTPS for development only
  let httpsOptions: https.ServerOptions | undefined;
  if (fs.existsSync(keyPath) && fs.existsSync(certPath) && fs.existsSync(caPath)) {
    httpsOptions = {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
      ca: fs.readFileSync(caPath),
      requestCert: true,
      rejectUnauthorized: true,
    };
  } else if (!allowInsecureHttp) {
    throw new Error(
      'mTLS certificates not found. Set ALLOW_INSECURE_MICROSERVICE_HTTP=true to run without HTTPS.',
    );
  } else {
    console.warn('mTLS certificates not found, running users service without HTTPS');
  }

  const app = await NestFactory.create(UsersModule, {
    httpsOptions,
  });

  app.useGlobalGuards(new GatewayOnlyGuard());

  await app.listen(3001, '0.0.0.0');
  const protocol = httpsOptions ? 'https' : 'http';
  console.log(`Users service is running on ${protocol}://0.0.0.0:3001`);
}
bootstrap();
