import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { PolicyEvaluatorService } from '../policy-evaluator.service';

describe('PolicyEvaluatorService (Casbin)', () => {
  let service: PolicyEvaluatorService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PolicyEvaluatorService,
        {
          provide: ConfigService,
          useValue: { get: (key: string) => process.env[key] },
        },
      ],
    }).compile();

    service = module.get<PolicyEvaluatorService>(PolicyEvaluatorService);
  });

  it('should allow authorized low-risk requests', async () => {
    const decision = await service.evaluatePolicies(
      { userId: 'u1', roles: ['user'] },
      0.2,
      '/users',
      'GET',
    );

    expect(decision).toEqual(
      expect.objectContaining({ decision: 'ALLOW', score: 0.2 }),
    );
  });

  it('should deny when policy does not allow access', async () => {
    const decision = await service.evaluatePolicies(
      { userId: 'u1', roles: ['user'] },
      0.2,
      '/admin',
      'GET',
    );

    expect(decision.decision).toBe('DENY');
    expect(decision.reason).toBe('Policy denied');
  });

  it('should challenge medium-risk authorized requests', async () => {
    const decision = await service.evaluatePolicies(
      { userId: 'u1', roles: ['user'] },
      0.6,
      '/users',
      'GET',
    );

    expect(decision.decision).toBe('CHALLENGE');
  });

  it('should deny high-risk authorized requests', async () => {
    const decision = await service.evaluatePolicies(
      { userId: 'u1', roles: ['user'] },
      0.9,
      '/users',
      'GET',
    );

    expect(decision.decision).toBe('DENY');
    expect(decision.reason).toBe('Risk score too high');
  });
});

