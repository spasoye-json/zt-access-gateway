import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ProxyService } from './proxy.service';
import { MtlsService } from '../shared/mtls.service';
import { ConfigModule } from '../config/config.module';
import { ServiceRegistryService } from './service-registry.service';

@Module({
  imports: [
    HttpModule,
    ConfigModule,
  ],
  providers: [ProxyService, MtlsService, ServiceRegistryService],
  exports: [ProxyService],
})
export class ProxyModule {}
