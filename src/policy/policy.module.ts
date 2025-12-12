import { Module } from '@nestjs/common';
import { PolicyService } from './policy.service';
import { PolicyController } from './policy.controller';
import { PolicyAdminController } from './policy-admin.controller';
import { SharedModule } from '../shared/shared.module';

@Module({
  imports: [SharedModule],
  controllers: [PolicyController, PolicyAdminController],
  providers: [PolicyService],
  exports: [PolicyService],
})
export class PolicyModule {}
