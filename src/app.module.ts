import { Module } from '@nestjs/common';
import { ConfigAppModule } from './config/config.module';
import { SharedModule } from './shared/shared.module';

@Module({
  imports: [ConfigAppModule, SharedModule],
  controllers: [],
  providers: [],
})
export class AppModule {}
