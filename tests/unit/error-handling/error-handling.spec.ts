import { Test, TestingModule } from '@nestjs/testing';
import { UnauthorizedException } from '@nestjs/common';
import { GatewayController } from "../../../src/gateway/gateway.controller";
import { AuthService } from "../../../src/auth/auth.service";
import { TrustScoreService } from "../../../src/trust-score/trust-score.service";
import { PolicyService } from "../../../src/policy/policy.service";
import { ProxyService } from "../../../src/proxy/proxy.service";
import { AuditService } from "../../../src/audit/audit.service";
import { MetricsService } from "../../../src/metrics/metrics.service";
import { MfaService } from "../../../src/mfa/mfa.service";

describe('Error Handling and Validation Tests', () => {
  let controller: GatewayController;
  let mockAuthService: Partial<AuthService>;
  let mockTrustScoreService: Partial<TrustScoreService>;
  let mockPolicyService: Partial<PolicyService>;
  let mockProxyService: Partial<ProxyService>;
  let mockAuditService: Partial<AuditService>;
  let mockMetricsService: Partial<MetricsService>;
  let mockMfaService: Partial<MfaService>;

  beforeEach(async () => {
    mockAuthService = {
      validateAuthorizationHeader: jest.fn(),
    };

    mockTrustScoreService = {
      calculateTrustScore: jest.fn(),
    };

    mockPolicyService = {
      evaluateAccess: jest.fn(),
    };

    mockProxyService = {
      forwardRequest: jest.fn(),
    };

    mockAuditService = {
      logAccessDecision: jest.fn(),
    };

    mockMetricsService = {
      recordRequestMetrics: jest.fn(),
    };

    mockMfaService = {
      initiateChallenge: jest.fn().mockResolvedValue({
        challengeId: 'chal-123',
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      }),
      isTokenValid: jest.fn().mockResolvedValue(false),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [GatewayController],
      providers: [
        { provide: AuthService, useValue: mockAuthService },
        { provide: TrustScoreService, useValue: mockTrustScoreService },
        { provide: PolicyService, useValue: mockPolicyService },
        { provide: ProxyService, useValue: mockProxyService },
        { provide: AuditService, useValue: mockAuditService },
        { provide: MetricsService, useValue: mockMetricsService },
        { provide: MfaService, useValue: mockMfaService },
      ],
    }).compile();

    controller = module.get<GatewayController>(GatewayController);
  });

  describe('Gateway Controller Error Handling', () => {
    it('should return 401 when no authorization header is present', async () => {
      const mockReq = {
        method: 'GET',
        url: '/users',
        connection: { remoteAddress: '127.0.0.1' },
        headers: {}
      };
      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockHeaders = {};
      const mockBody = {};
      const mockQuery = {};

      await controller.handleRequest(mockReq, mockRes, mockHeaders, mockBody, mockQuery);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Authorization header is required'
      });
    });

    it('should return 401 when token format is invalid', async () => {
      const mockReq = {
        method: 'GET',
        url: '/users',
        connection: { remoteAddress: '127.0.0.1' },
        headers: {}
      };
      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockHeaders = { authorization: 'InvalidFormatToken' };
      const mockBody = {};
      const mockQuery = {};

      (mockAuthService.validateAuthorizationHeader as jest.Mock).mockRejectedValue(
        new UnauthorizedException('Invalid token format. Use Bearer token.'),
      );

      await controller.handleRequest(mockReq, mockRes, mockHeaders, mockBody, mockQuery);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Invalid token format. Use Bearer token.'
      });
    });

    it('should return 401 when token is invalid', async () => {
      const mockReq = {
        method: 'GET',
        url: '/users',
        connection: { remoteAddress: '127.0.0.1' },
        headers: {}
      };
      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockHeaders = { authorization: 'Bearer invalid-token' };
      const mockBody = {};
      const mockQuery = {};

      (mockAuthService.validateAuthorizationHeader as jest.Mock).mockRejectedValue(
        new UnauthorizedException('Invalid token'),
      );

      await controller.handleRequest(mockReq, mockRes, mockHeaders, mockBody, mockQuery);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Invalid token'
      });
    });

    it('should return 403 when policy decision is DENY', async () => {
      const mockReq = {
        method: 'GET',
        url: '/users',
        connection: { remoteAddress: '127.0.0.1' },
        headers: {}
      };
      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockHeaders = { authorization: 'Bearer valid-token' };
      const mockBody = {};
      const mockQuery = {};

      (mockAuthService.validateAuthorizationHeader as jest.Mock).mockResolvedValue({
        userId: 'user123',
        roles: ['user'],
        sessionId: '',
      });
      (mockTrustScoreService.calculateTrustScore as jest.Mock).mockResolvedValue({
        score: 0.8,
        level: 'HIGH',
        factors: {},
      });
      (mockPolicyService.evaluateAccess as jest.Mock).mockResolvedValue({
        decision: 'DENY',
        reason: 'High risk score',
      });

      await controller.handleRequest(mockReq, mockRes, mockHeaders, mockBody, mockQuery);

      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Forbidden',
        message: 'High risk score'
      });
    });

    it('should return 401 when policy decision is CHALLENGE', async () => {
      const mockReq = {
        method: 'GET',
        url: '/users',
        connection: { remoteAddress: '127.0.0.1' },
        headers: {}
      };
      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockHeaders = { authorization: 'Bearer valid-token' };
      const mockBody = {};
      const mockQuery = {};

      (mockAuthService.validateAuthorizationHeader as jest.Mock).mockResolvedValue({
        userId: 'user123',
        roles: ['user'],
        sessionId: '',
      });
      (mockTrustScoreService.calculateTrustScore as jest.Mock).mockResolvedValue({
        score: 0.6,
        level: 'MEDIUM',
        factors: {},
      });
      (mockPolicyService.evaluateAccess as jest.Mock).mockResolvedValue({
        decision: 'CHALLENGE',
        reason: 'Additional verification required',
      });

      await controller.handleRequest(mockReq, mockRes, mockHeaders, mockBody, mockQuery);

      expect(mockMfaService.initiateChallenge).toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Challenge Required',
        message: 'Additional verification required',
        challengeId: 'chal-123',
        expiresAt: expect.any(String),
      });
    });

    it('should proceed when policy decision is CHALLENGE but MFA token is valid', async () => {
      const mockReq = {
        method: 'GET',
        url: '/users',
        connection: { remoteAddress: '127.0.0.1' },
        headers: {}
      };
      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockHeaders = { authorization: 'Bearer valid-token', 'x-mfa-token': 'mfa-123' };
      const mockBody = {};
      const mockQuery = {};

      (mockAuthService.validateAuthorizationHeader as jest.Mock).mockResolvedValue({
        userId: 'user123',
        roles: ['user'],
        sessionId: '',
      });
      (mockTrustScoreService.calculateTrustScore as jest.Mock).mockResolvedValue({
        score: 0.6,
        level: 'MEDIUM',
        factors: {},
      });
      (mockPolicyService.evaluateAccess as jest.Mock).mockResolvedValue({
        decision: 'CHALLENGE',
        reason: 'Additional verification required',
      });
      (mockMfaService.isTokenValid as jest.Mock).mockResolvedValue(true);
      (mockProxyService.forwardRequest as jest.Mock).mockResolvedValue({
        status: 200,
        data: { success: true },
        headers: {},
      });

      await controller.handleRequest(mockReq, mockRes, mockHeaders, mockBody, mockQuery);

      expect(mockProxyService.forwardRequest).toHaveBeenCalled();
      expect(mockRes.status).toHaveBeenCalledWith(200);
      expect(mockRes.json).toHaveBeenCalledWith({ success: true });
    });

    it('should handle exceptions during token validation', async () => {
      const mockReq = {
        method: 'GET',
        url: '/users',
        connection: { remoteAddress: '127.0.0.1' },
        headers: {}
      };
      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockHeaders = { authorization: 'Bearer valid-token' };
      const mockBody = {};
      const mockQuery = {};

      (mockAuthService.validateAuthorizationHeader as jest.Mock).mockRejectedValue(
        new Error('Internal error'),
      );

      await controller.handleRequest(mockReq, mockRes, mockHeaders, mockBody, mockQuery);

      // The actual behavior in the controller is to return 401 when token validation fails
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Invalid or expired token'
      });
    });

    it('should call audit service even when an error occurs', async () => {
      const mockReq = {
        method: 'GET',
        url: '/users',
        connection: { remoteAddress: '127.0.0.1' },
        headers: {}
      };
      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockHeaders = { authorization: 'Bearer valid-token' };
      const mockBody = {};
      const mockQuery = {};

      (mockAuthService.validateAuthorizationHeader as jest.Mock).mockRejectedValue(
        new Error('Internal error'),
      );

      await controller.handleRequest(mockReq, mockRes, mockHeaders, mockBody, mockQuery);

      // Audit service should be called to log the error condition
      expect(mockAuditService.logAccessDecision).toHaveBeenCalled();
    });

    it('should handle proxy forwarding errors gracefully', async () => {
      const mockReq = {
        method: 'GET',
        url: '/users',
        connection: { remoteAddress: '127.0.0.1' },
        headers: {}
      };
      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockHeaders = { authorization: 'Bearer valid-token' };
      const mockBody = {};
      const mockQuery = {};

      (mockAuthService.validateAuthorizationHeader as jest.Mock).mockResolvedValue({
        userId: 'user123',
        roles: ['user'],
        sessionId: '',
      });
      (mockTrustScoreService.calculateTrustScore as jest.Mock).mockResolvedValue({
        score: 0.2,
        level: 'LOW',
        factors: {},
      });
      (mockPolicyService.evaluateAccess as jest.Mock).mockResolvedValue({
        decision: 'ALLOW',
        reason: 'Valid request',
      });
      (mockProxyService.forwardRequest as jest.Mock).mockRejectedValue(new Error('Service unavailable'));

      await controller.handleRequest(mockReq, mockRes, mockHeaders, mockBody, mockQuery);

      expect(mockRes.status).toHaveBeenCalledWith(502);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Bad Gateway',
        message: 'Failed to reach target service'
      });
    });
  });

  describe('Input Validation', () => {
    it('should validate token length', async () => {
      const mockReq = {
        method: 'GET',
        url: '/users',
        connection: { remoteAddress: '127.0.0.1' },
        headers: {}
      };
      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      // Very short token
      const mockHeaders = { authorization: 'Bearer short' };
      const mockBody = {};
      const mockQuery = {};

      (mockAuthService.validateAuthorizationHeader as jest.Mock).mockRejectedValue(
        new UnauthorizedException('Invalid token length'),
      );

      await controller.handleRequest(mockReq, mockRes, mockHeaders, mockBody, mockQuery);

      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Invalid token length'
      });
    });

    it('should validate path to prevent traversal attacks', async () => {
      const mockReq = {
        method: 'GET',
        url: '/users/../../../etc/passwd',
        connection: { remoteAddress: '127.0.0.1' },
        headers: {}
      };
      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      const mockHeaders = { authorization: 'Bearer valid-token' };
      const mockBody = {};
      const mockQuery = {};

      (mockAuthService.validateAuthorizationHeader as jest.Mock).mockResolvedValue({
        userId: 'user123',
        roles: ['user'],
        sessionId: '',
      });
      (mockTrustScoreService.calculateTrustScore as jest.Mock).mockResolvedValue({
        score: 0.2,
        level: 'LOW',
        factors: {},
      });
      (mockPolicyService.evaluateAccess as jest.Mock).mockResolvedValue({
        decision: 'ALLOW',
        reason: 'Valid request',
      });

      await controller.handleRequest(mockReq, mockRes, mockHeaders, mockBody, mockQuery);

      expect(mockRes.status).toHaveBeenCalledWith(400);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Bad Request',
        message: 'Invalid path'
      });
    });
  });
});
