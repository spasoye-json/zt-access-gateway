import { Module } from '@nestjs/common';
import { GatewayController } from './gateway.controller';
import { AuthModule } from '../auth/auth.module';
import { TrustScoreModule } from '../trust-score/trust-score.module';
import { PolicyModule } from '../policy/policy.module';
import { ProxyModule } from '../proxy/proxy.module';
import { AuditModule } from '../audit/audit.module';
import { MetricsModule } from '../metrics/metrics.module';
import { MfaModule } from '../mfa/mfa.module';

@Module({
  imports: [
    AuthModule,
    TrustScoreModule,
    PolicyModule,
    ProxyModule,
    AuditModule,
    MetricsModule,
    MfaModule,
  ],
  controllers: [GatewayController],
})
export class GatewayModule {}
