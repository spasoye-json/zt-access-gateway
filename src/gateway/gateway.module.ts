import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { TrustScoreModule } from '../trust-score/trust-score.module';
import { PolicyModule } from '../policy/policy.module';
import { ProxyModule } from '../proxy/proxy.module';
import { AuditModule } from '../audit/audit.module';
import { MetricsModule } from '../metrics/metrics.module';
import { MfaModule } from '../mfa/mfa.module';
import { GatewayMiddleware } from './gateway.middleware';

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
  providers: [GatewayMiddleware],
})
export class GatewayModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(GatewayMiddleware)
      .exclude(
        { path: 'mfa/verify', method: RequestMethod.POST },
        { path: 'metrics', method: RequestMethod.GET },
        { path: 'policy/(.*)', method: RequestMethod.ALL },
        { path: 'trust-score/calculate', method: RequestMethod.GET },
        { path: 'audit/health', method: RequestMethod.GET },
      )
      .forRoutes({ path: '*', method: RequestMethod.ALL });
  }
}
