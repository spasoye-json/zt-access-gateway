import { Module } from '@nestjs/common';
import { GatewayController } from './gateway.controller';
import { AuthModule } from '../auth/auth.module';
import { TrustScoreModule } from '../trust-score/trust-score.module';
import { PolicyModule } from '../policy/policy.module';
import { ProxyModule } from '../proxy/proxy.module';
import { AuditModule } from '../audit/audit.module';
import { MetricsModule } from '../metrics/metrics.module';

@Module({
  imports: [
    AuthModule,
    TrustScoreModule,
    PolicyModule,
    ProxyModule,
    AuditModule,
    MetricsModule,
  ],
  controllers: [GatewayController],
})
export class GatewayModule {}
