import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { Reflector } from '@nestjs/core';
import { AuthService } from '../auth/auth.service';
import { TrustScoreService } from '../trust-score/trust-score.service';
import { PolicyService } from '../policy/policy.service';
import { AuditService } from '../audit/audit.service';
import { MetricsService } from '../metrics/metrics.service';

@Injectable()
export class GatewayInterceptor implements NestInterceptor {
  private readonly logger = new Logger(GatewayInterceptor.name);

  constructor(
    private reflector: Reflector,
    private authService: AuthService,
    private trustScoreService: TrustScoreService,
    private policyService: PolicyService,
    private auditService: AuditService,
    private metricsService: MetricsService,
  ) {}

  async intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<any>> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    const startTime = Date.now();

    const requestId = this.generateRequestId();
    const method = request.method;
    const path = request.url;
    
    this.logger.log(`Intercepting request: ${method} ${path} with ID: ${requestId}`);

    // Check if this route should be public (bypass gateway logic)
    const isPublic = this.reflector.getAllAndOverride<boolean>('isPublic', [
      context.getHandler(),
      context.getClass(),
    ]);
    
    if (isPublic) {
      return next.handle();
    }

    try {
      // Extract important headers
      const authHeader = request.headers['authorization'];
      const deviceId = request.headers['x-device-id'] || 'unknown';
      const ip = request.headers['x-forwarded-for'] || request.connection.remoteAddress || 'unknown';
      const userAgent = request.headers['user-agent'] || 'unknown';
      const body = request.body;

      if (!authHeader) {
        await this.auditService.logAccessDecision({
          requestId,
          userId: 'unknown',
          microservice: 'unknown',
          decision: 'DENY',
          riskScore: 1.0,
          policyApplied: 'no-auth-policy',
          metadata: { reason: 'No authorization header' },
        });

        response.status(401).json({ error: 'Unauthorized: No token provided' });
        return;
      }

      // Step 1: Authentication
      const token = authHeader.replace('Bearer ', '');
      const userClaims = await this.authService.validateToken(token);

      if (!userClaims) {
        await this.auditService.logAccessDecision({
          requestId,
          userId: 'unknown',
          microservice: 'unknown',
          decision: 'DENY',
          riskScore: 1.0,
          policyApplied: 'invalid-token-policy',
          metadata: { reason: 'Invalid token' },
        });

        response.status(401).json({ error: 'Unauthorized: Invalid token' });
        return;
      }

      // Step 2: Trust Score Calculation
      const trustScoreResult = await this.trustScoreService.calculateTrustScore(
        userClaims.userId,
        deviceId,
        ip,
        userAgent,
      );

      // Step 3: Policy Evaluation
      const policyDecision = await this.policyService.evaluateAccess(
        userClaims,
        trustScoreResult.score,
        path, // resource
        method, // action
      );

      // Step 4: Record audit log based on policy decision
      await this.auditService.logAccessDecision({
        requestId,
        userId: userClaims.userId,
        microservice: this.getTargetMicroservice(path),
        decision: policyDecision.decision,
        riskScore: trustScoreResult.score,
        policyApplied: 'dynamic-policy',
        metadata: {
          path,
          method,
          trustFactors: trustScoreResult.factors,
          decisionReason: policyDecision.reason,
        },
      });

      // Step 5: Handle policy decision
      if (policyDecision.decision === 'DENY') {
        // Record metrics for denied request
        await this.metricsService.recordRequestMetrics({
          requestId,
          evaluationLatencyMs: Date.now() - startTime,
          requestForwardLatencyMs: 0,
          totalGatewayLatencyMs: Date.now() - startTime,
          decision: 'DENY',
          trustScore: trustScoreResult.score,
        });

        response.status(403).json({ 
          error: 'Forbidden', 
          reason: policyDecision.reason 
        });
        return;
      } else if (policyDecision.decision === 'CHALLENGE') {
        // For now, just return a challenge response
        // In a real implementation, this would trigger MFA or other challenge mechanisms
        await this.metricsService.recordRequestMetrics({
          requestId,
          evaluationLatencyMs: Date.now() - startTime,
          requestForwardLatencyMs: 0,
          totalGatewayLatencyMs: Date.now() - startTime,
          decision: 'CHALLENGE',
          trustScore: trustScoreResult.score,
        });

        response.status(401).json({ 
          error: 'Challenge Required', 
          reason: policyDecision.reason 
        });
        return;
      }

      // If we reach here, the request is allowed
      // Add user claims and trust score to request for downstream use
      request.userClaims = userClaims;
      request.trustScore = trustScoreResult.score;
      request.gatewayRequestId = requestId;

      // Continue with the request
      return next.handle().pipe(
        tap(async () => {
          // Record metrics after the request completes
          await this.metricsService.recordRequestMetrics({
            requestId,
            evaluationLatencyMs: Date.now() - startTime,
            requestForwardLatencyMs: 0, // This would be updated in proxy service
            totalGatewayLatencyMs: Date.now() - startTime,
            decision: 'ALLOW',
            trustScore: trustScoreResult.score,
          });
        })
      );
    } catch (error) {
      this.logger.error('Gateway interceptor error:', error);
      
      await this.auditService.logAccessDecision({
        requestId,
        userId: 'unknown',
        microservice: 'unknown',
        decision: 'DENY',
        riskScore: 1.0,
        policyApplied: 'error-policy',
        metadata: { reason: 'Gateway error', error: error.message },
      });

      response.status(500).json({ error: 'Internal Server Error' });
      return;
    }
  }

  private getTargetMicroservice(path: string): string {
    // Simple routing logic based on path
    // In a real implementation, this would come from configuration
    if (path.startsWith('/users')) {
      return 'users-service';
    } else if (path.startsWith('/orders')) {
      return 'orders-service';
    } else if (path.startsWith('/permissions')) {
      return 'permissions-service';
    } else {
      return 'default-service';
    }
  }

  private generateRequestId(): string {
    return 'req-' + Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
  }
}