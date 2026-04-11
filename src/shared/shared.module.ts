import { Module } from '@nestjs/common';
import { MtlsService } from './mtls.service';
import { ConfigModule } from '../config/config.module';

@Module({
  imports: [ConfigModule],
  providers: [MtlsService],
  exports: [MtlsService],
})
export class SharedModule {}
