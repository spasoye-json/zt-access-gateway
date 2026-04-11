import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { ProxyService } from './proxy.service';
import { ConfigModule } from '../config/config.module';
import { ServiceRegistryService } from './service-registry.service';
import { SharedModule } from '../shared/shared.module';

@Module({
  imports: [
    HttpModule,
    ConfigModule,
    SharedModule
  ],
  providers: [ProxyService, ServiceRegistryService],
  exports: [ProxyService],
})
export class ProxyModule {}
