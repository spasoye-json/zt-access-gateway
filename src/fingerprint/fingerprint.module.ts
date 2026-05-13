import { Module } from '@nestjs/common';
import { SharedModule } from '../shared/shared.module';
import { FingerprintStore } from './fingerprint.store';
import { Ja4hMiddleware } from './ja4h.middleware';

/**
 * FingerprintModule — provides JA4H fingerprinting infrastructure.
 *
 * Exports FingerprintStore so any module that imports FingerprintModule can
 * inject it (e.g. HoneypotModule's ShadowController writes to the blacklist).
 *
 * Exports Ja4hMiddleware so AppModule can register it via MiddlewareConsumer
 * with full NestJS DI support (required for FingerprintStore injection).
 */
@Module({
  imports: [SharedModule],
  providers: [FingerprintStore, Ja4hMiddleware],
  exports: [FingerprintStore, Ja4hMiddleware],
})
export class FingerprintModule {}
