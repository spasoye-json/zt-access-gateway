import { Controller, Request, Response, Body, Query, Headers, BadRequestException, UnauthorizedException, All } from '@nestjs/common';
import { AuthService, UserClaims } from '../auth/auth.service';
import { Public } from '../auth/public.decorator';
import { TrustScoreService, TrustScoreResult } from '../trust-score/trust-score.service';
import { PolicyService } from '../policy/policy.service';
import { ProxyService } from '../proxy/proxy.service';
import { AuditService } from '../audit/audit.service';
import { MetricsService } from '../metrics/metrics.service';
import { PolicyDecision } from '../policy/policy-evaluator.service';
import { extractClientIp, resolveDeviceId } from '../shared/request-context.util';
import { MfaService } from '../mfa/mfa.service';

@Public()
@Controller()
export class GatewayController {
  constructor(
    private authService: AuthService,
    private trustScoreService: TrustScoreService,
    private policyService: PolicyService,
    private proxyService: ProxyService,
    private auditService: AuditService,
    private metricsService: MetricsService,
    private mfaService: MfaService,
  ) {}

  @All('*')
  async handleRequest(
    @Request() req,
    @Response() res,
    @Headers() headers,
    @Body() body,
    @Query() query,
  ) {
    const startTime = Date.now();
    const requestId = this.generateRequestId();
    const method = req.method;
    const path = req.url;
    
    console.log(`Processing request: ${method} ${path} with ID: ${requestId}`);

    try {
      // Validate required headers
      if (!headers || typeof headers !== 'object') {
        throw new BadRequestException('Invalid headers provided');
      }

      // Extract important headers
      const authHeader = headers['authorization'];
      const deviceId = resolveDeviceId(headers['x-device-id']);
      const ip = extractClientIp(req);
      const userAgent =
        typeof headers['user-agent'] === 'string' && headers['user-agent'].length > 0
          ? headers['user-agent']
          : 'unknown';
      const mfaToken =
        typeof headers['x-mfa-token'] === 'string' && headers['x-mfa-token'].length > 0
          ? headers['x-mfa-token']
          : undefined;
      const sanitizedHeaders = { ...headers };
      delete sanitizedHeaders['x-mfa-token'];
      delete sanitizedHeaders['X-Mfa-Token'];

      if (!authHeader || typeof authHeader !== 'string') {
        await this.auditService.logAccessDecision({
          requestId,
          userId: 'unknown',
          microservice: 'unknown',
          decision: 'DENY',
          riskScore: 1.0,
          policyApplied: 'no-auth-policy',
          metadata: { reason: 'No authorization header' },
        });

        return res.status(401).json({ 
          error: 'Unauthorized', 
          message: 'Authorization header is required' 
        });
      }

      // Step 1: Authentication
      let userClaims: UserClaims;
      try {
        userClaims = await this.authService.validateAuthorizationHeader(authHeader);
      } catch (authError) {
        const message =
          authError instanceof UnauthorizedException
            ? authError.message
            : 'Invalid or expired token';

        await this.auditService.logAccessDecision({
          requestId,
          userId: 'unknown',
          microservice: 'unknown',
          decision: 'DENY',
          riskScore: 1.0,
          policyApplied: 'invalid-token-policy',
          metadata: { 
            reason: 'Token validation failed',
            message,
            error: authError.message,
          },
        });

        return res.status(401).json({ 
          error: 'Unauthorized', 
          message,
        });
      }

      // Step 2: Trust Score Calculation
      let trustScoreResult: TrustScoreResult;
      try {
        trustScoreResult = await this.trustScoreService.calculateTrustScore(
          userClaims.userId,
          deviceId,
          ip,
          userAgent,
        );
      } catch (trustError) {
        console.error('Trust score calculation error:', trustError);
        await this.auditService.logAccessDecision({
          requestId,
          userId: userClaims.userId,
          microservice: this.getTargetMicroservice(path),
          decision: 'DENY',
          riskScore: 1.0,
          policyApplied: 'trust-score-error-policy',
          metadata: { 
            reason: 'Trust score calculation failed', 
            error: trustError.message 
          },
        });

        return res.status(500).json({ 
          error: 'Internal Server Error', 
          message: 'Trust score calculation failed' 
        });
      }

      // Step 3: Policy Evaluation
      let policyDecision: PolicyDecision;
      try {
        policyDecision = await this.policyService.evaluateAccess(
          userClaims,
          trustScoreResult.score,
          path, // resource
          method, // action
        );
      } catch (policyError) {
        console.error('Policy evaluation error:', policyError);
        await this.auditService.logAccessDecision({
          requestId,
          userId: userClaims.userId,
          microservice: this.getTargetMicroservice(path),
          decision: 'DENY',
          riskScore: trustScoreResult.score,
          policyApplied: 'policy-evaluation-error-policy',
          metadata: { 
            reason: 'Policy evaluation failed', 
            error: policyError.message 
          },
        });

        return res.status(500).json({ 
          error: 'Internal Server Error', 
          message: 'Policy evaluation failed' 
        });
      }

      let mfaSatisfied = false;
      if (policyDecision.decision === 'CHALLENGE') {
        if (await this.mfaService.isTokenValid(userClaims.userId, mfaToken)) {
          mfaSatisfied = true;
          policyDecision = {
            decision: 'ALLOW',
            reason: 'MFA challenge satisfied',
            score: trustScoreResult.score,
          };
        }
      }

      // Step 4: Record audit log based on policy decision
      try {
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
            mfaSatisfied,
          },
        });
      } catch (auditError) {
        console.error('Audit logging error:', auditError);
        // Don't fail the request if audit logging fails, but log it
        console.warn('Failed to log audit decision:', auditError.message);
      }

      // Step 5: Handle policy decision
      if (policyDecision.decision === 'DENY') {
        // Record metrics for denied request
        try {
          await this.metricsService.recordRequestMetrics({
            requestId,
            evaluationLatencyMs: Date.now() - startTime,
            requestForwardLatencyMs: 0,
            totalGatewayLatencyMs: Date.now() - startTime,
            decision: 'DENY',
            trustScore: trustScoreResult.score,
          });
        } catch (metricsError) {
          console.warn('Failed to record metrics for denied request:', metricsError.message);
        }

        return res.status(403).json({ 
          error: 'Forbidden', 
          message: policyDecision.reason 
        });
      } else if (policyDecision.decision === 'CHALLENGE') {
        // For now, just return a challenge response
        // In a real implementation, this would trigger MFA or other challenge mechanisms
        try {
          await this.metricsService.recordRequestMetrics({
            requestId,
            evaluationLatencyMs: Date.now() - startTime,
            requestForwardLatencyMs: 0,
            totalGatewayLatencyMs: Date.now() - startTime,
            decision: 'CHALLENGE',
            trustScore: trustScoreResult.score,
          });
        } catch (metricsError) {
          console.warn('Failed to record metrics for challenged request:', metricsError.message);
        }

        const challenge = await this.mfaService.initiateChallenge({
          userId: userClaims.userId,
          sessionId: userClaims.sessionId,
          method,
          path,
          deviceId,
          ip,
        });

        return res.status(401).json({
          error: 'Challenge Required',
          message: policyDecision.reason,
          challengeId: challenge.challengeId,
          expiresAt: challenge.expiresAt,
        });
      } else { // ALLOW
        // Validate that the path is safe before forwarding
        if (!this.isValidPath(path)) {
          await this.auditService.logAccessDecision({
            requestId,
            userId: userClaims.userId,
            microservice: this.getTargetMicroservice(path),
            decision: 'DENY',
            riskScore: trustScoreResult.score,
            policyApplied: 'invalid-path-policy',
            metadata: { reason: 'Invalid path detected' },
          });

          return res.status(400).json({ 
            error: 'Bad Request', 
            message: 'Invalid path' 
          });
        }

        // Step 6: Forward to target microservice via mTLS
        const targetMicroservice = this.getTargetMicroservice(path);
        let forwardedResponse;
        const forwardStartTime = Date.now();
        
        try {
          forwardedResponse = await this.proxyService.forwardRequest(
            targetMicroservice,
            method,
            path,
            sanitizedHeaders,
            body,
            userClaims,
            trustScoreResult.score,
          );
        } catch (proxyError) {
          console.error('Proxy forwarding error:', proxyError);
          await this.auditService.logAccessDecision({
            requestId,
            userId: userClaims.userId,
            microservice: targetMicroservice,
            decision: 'DENY',
            riskScore: trustScoreResult.score,
            policyApplied: 'proxy-error-policy',
            metadata: { 
              reason: 'Proxy forwarding failed', 
              error: proxyError.message 
            },
          });

          return res.status(502).json({ 
            error: 'Bad Gateway', 
            message: 'Failed to reach target service' 
          });
        }

        // Record metrics for allowed request
        try {
          await this.metricsService.recordRequestMetrics({
            requestId,
            evaluationLatencyMs: forwardStartTime - startTime,
            requestForwardLatencyMs: Date.now() - forwardStartTime,
            totalGatewayLatencyMs: Date.now() - startTime,
            decision: 'ALLOW',
            trustScore: trustScoreResult.score,
          });
        } catch (metricsError) {
          console.warn('Failed to record metrics for allowed request:', metricsError.message);
        }

        // Return the actual response from the microservice
        return res.status(forwardedResponse.status).json(forwardedResponse.data);
      }
    } catch (error) {
      console.error('Gateway error:', error);
      
      // Log the error for audit purposes (best effort)
      try {
        await this.auditService.logAccessDecision({
          requestId,
          userId: 'unknown',
          microservice: 'unknown',
          decision: 'DENY',
          riskScore: 1.0,
          policyApplied: 'error-policy',
          metadata: { 
            reason: 'Gateway processing error', 
            error: error.message,
            stack: error.stack,
          },
        });
      } catch (auditError) {
        console.error('Failed to log audit for error condition:', auditError);
      }

      // Return appropriate error response based on error type
      if (error instanceof BadRequestException) {
        return res.status(400).json({ 
          error: 'Bad Request', 
          message: error.message 
        });
      } else {
        return res.status(500).json({ 
          error: 'Internal Server Error', 
          message: 'An unexpected error occurred' 
        });
      }
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

  private isValidPath(path: string): boolean {
    // Basic path validation to prevent path traversal attacks
    if (path.includes('../') || path.includes('..\\')) {
      return false;
    }
    
    // Prevent protocol schemes in path (potential SSRF)
    if (/^https?:\/\//.test(path)) {
      return false;
    }
    
    return true;
  }
}
