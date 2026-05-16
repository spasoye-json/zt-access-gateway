import { Module } from '@nestjs/common';
import { ConfigAppModule } from '../../config/config.module';
import { DemoModeService } from './demo-mode.service';

@Module({
  imports: [ConfigAppModule],
  providers: [DemoModeService],
  exports: [DemoModeService],
})
export class DemoModeModule {}
