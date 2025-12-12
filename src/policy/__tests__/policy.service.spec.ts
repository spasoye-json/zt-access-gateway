import { Test, TestingModule } from '@nestjs/testing';
import { PolicyService } from '../policy.service';
import { PolicyEvaluatorService } from '../../shared/policy-evaluator.service';

describe('PolicyService', () => {
  let service: PolicyService;
  let mockPolicyEvaluator: Partial<PolicyEvaluatorService>;

  beforeEach(async () => {
    mockPolicyEvaluator = {
      evaluatePolicies: jest.fn(),
      listPolicies: jest.fn().mockResolvedValue([
        ['role:user', '/users', 'GET'],
        ['role:admin', '/admin', '(GET|POST)'],
      ]),
      addPolicy: jest.fn().mockResolvedValue(true),
      removePolicy: jest.fn().mockResolvedValue(true),
      reloadPolicies: jest.fn().mockResolvedValue(undefined),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PolicyService,
        { provide: PolicyEvaluatorService, useValue: mockPolicyEvaluator },
      ],
    }).compile();

    service = module.get<PolicyService>(PolicyService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('evaluateAccess', () => {
    it('should return policy decision when all parameters are valid', async () => {
      const mockUserClaims = { userId: 'user123', roles: ['user'], sessionId: '' };
      const mockDecision = { decision: 'ALLOW', reason: 'Low risk' } as const;
      
      (mockPolicyEvaluator.evaluatePolicies as jest.Mock).mockResolvedValue(mockDecision);

      const result = await service.evaluateAccess(
        mockUserClaims,
        0.2,
          '/users',
        'GET'
      );

      expect(result).toEqual(mockDecision);
      expect(mockPolicyEvaluator.evaluatePolicies).toHaveBeenCalledWith(
        mockUserClaims,
        0.2,
        '/users',
        'GET'
      );
    });

    it('should handle different policy decisions', async () => {
      const mockUserClaims = { userId: 'user123', roles: ['user'], sessionId: "" };
      const mockDecision = { decision: 'DENY', reason: 'High risk' } as const;
      
      (mockPolicyEvaluator.evaluatePolicies as jest.Mock).mockResolvedValue(mockDecision);

      const result = await service.evaluateAccess(
        mockUserClaims,
        0.8,
        '/admin',
        'POST'
      );

      expect(result.decision).toBe('DENY');
      expect(result.reason).toBe('High risk');
    });
  });

  describe('policy management helpers', () => {
    it('should list policies from evaluator', async () => {
      const policies = await service.listPolicies();
      expect(policies).toHaveLength(2);
      expect(policies[0]).toEqual({
        subject: 'role:user',
        resource: '/users',
        action: 'GET',
      });
    });

    it('should add policies via evaluator', async () => {
      const added = await service.addPolicy({
        subject: 'role:auditor',
        resource: '/audit',
        action: 'GET',
      });
      expect(added).toBe(true);
      expect(mockPolicyEvaluator.addPolicy).toHaveBeenCalled();
    });

    it('should remove policies via evaluator', async () => {
      const removed = await service.removePolicy({
        subject: 'role:user',
        resource: '/users',
        action: 'GET',
      });
      expect(removed).toBe(true);
      expect(mockPolicyEvaluator.removePolicy).toHaveBeenCalled();
    });

    it('should reload policies', async () => {
      await service.reloadPolicies();
      expect(mockPolicyEvaluator.reloadPolicies).toHaveBeenCalled();
    });
  });
});
