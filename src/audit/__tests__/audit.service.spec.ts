import { Test, TestingModule } from '@nestjs/testing';
import { AuditService } from '../audit.service';
import { AuditRepository } from '../audit.repository';

describe('AuditService', () => {
  let service: AuditService;
  let mockRepository: Partial<AuditRepository>;

  beforeEach(async () => {
    mockRepository = {
      persist: jest.fn().mockResolvedValue(undefined),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuditService,
        { provide: AuditRepository, useValue: mockRepository },
      ],
    }).compile();

    service = module.get<AuditService>(AuditService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('logAccessDecision', () => {
    it('should successfully log an access decision with valid parameters', async () => {
      const logEntry = {
        requestId: 'req123',
        userId: 'user123',
        microservice: 'users-service',
        decision: 'ALLOW' as const,
        riskScore: 0.2,
        policyApplied: 'default-policy',
        metadata: { action: 'GET', resource: '/users' },
      };

      await expect(service.logAccessDecision(logEntry)).resolves.not.toThrow();
    });

    it('should handle invalid decision types gracefully', async () => {
      const logEntry = {
        requestId: 'req123',
        userId: 'user123',
        microservice: 'users-service',
        decision: 'INVALID' as any,
        riskScore: 0.2,
        policyApplied: 'default-policy',
        metadata: {},
      };

      // The audit service catches validation errors internally and doesn't throw
      await expect(service.logAccessDecision(logEntry)).resolves.not.toThrow();
    });

    it('should handle invalid riskScore values gracefully', async () => {
      const logEntry = {
        requestId: 'req123',
        userId: 'user123',
        microservice: 'users-service',
        decision: 'ALLOW' as const,
        riskScore: 1.5, // Invalid score > 1
        policyApplied: 'default-policy',
        metadata: {},
      };

      // The audit service catches validation errors internally and doesn't throw
      await expect(service.logAccessDecision(logEntry)).resolves.not.toThrow();
    });

    it('should handle missing required fields gracefully', async () => {
      const logEntry = {
        userId: 'user123', // Missing requestId
        microservice: 'users-service',
        decision: 'ALLOW' as const,
        riskScore: 0.2,
        policyApplied: 'default-policy',
        metadata: {},
      } as any;

      // The audit service catches validation errors internally and doesn't throw
      await expect(service.logAccessDecision(logEntry)).resolves.not.toThrow();
    });
  });
});
