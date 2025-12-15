import { Module } from '@nestjs/common';
import { MtlsService } from './mtls.service';

@Module({
  providers: [
    MtlsService,
  ],
  exports: [
    MtlsService,
  ],
})
export class SharedModule {}