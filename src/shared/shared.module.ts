import { Module } from '@nestjs/common';
import { JwtService } from './jwt.service';
import { MtlsService } from './mtls.service';
import { PolicyEvaluatorService } from './policy-evaluator.service';

@Module({
  providers: [
    JwtService,
    MtlsService,
    PolicyEvaluatorService,
  ],
  exports: [
    JwtService,
    MtlsService,
    PolicyEvaluatorService,
  ],
})
export class SharedModule {}