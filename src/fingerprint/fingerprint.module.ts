import { Module } from '@nestjs/common';
import { FingerprintStore } from './fingerprint.store';

@Module({
  providers: [FingerprintStore],
  exports: [FingerprintStore],
})
export class FingerprintModule {}
