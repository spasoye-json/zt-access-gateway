import { Module } from '@nestjs/common';
import { PolicyService } from './policy.service';
import { PolicyController } from './policy.controller';
import { PolicyAdminController } from './policy-admin.controller';
import { TrustScoreModule } from '../trust-score/trust-score.module';
import { PolicyEvaluatorService } from './policy-evaluator.service';

@Module({
  imports: [TrustScoreModule],
  controllers: [PolicyController, PolicyAdminController],
  providers: [PolicyService, PolicyEvaluatorService],
  exports: [PolicyService],
})
export class PolicyModule {}
