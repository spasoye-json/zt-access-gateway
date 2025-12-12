import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from '../auth.service';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '../../shared/jwt.service';

describe('AuthService', () => {
  let service: AuthService;
  let mockConfigService: Partial<ConfigService>;
  const jwtService = new JwtService();

  beforeEach(async () => {
    mockConfigService = {
      get: jest.fn((key: string) => process.env[key]),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: ConfigService, useValue: mockConfigService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('validateToken', () => {
    it('should return user claims when token is valid', async () => {
      const mockClaims = { userId: '123', roles: ['user'] };
      process.env.JWT_SECRET = 'test-secret';

      const token = await jwtService.sign(mockClaims, 'test-secret');

      const result = await service.validateToken(token);
      expect(result).toEqual(expect.objectContaining(mockClaims));
    });

    it('should reject invalid token with exception', async () => {
      process.env.JWT_SECRET = 'test-secret';

      await expect(service.validateToken('invalid-token')).rejects.toThrow();
    });

    it('should throw UnauthorizedException for invalid token format', async () => {
      await expect(service.validateToken('')).rejects.toThrow();
    });
  });

  describe('extractBearerToken', () => {
    it('should extract bearer token from authorization header', () => {
      const token = service.extractBearerToken('Bearer abcdefghijklmnop');
      expect(token).toBe('abcdefghijklmnop');
    });

    it('should reject invalid authorization header format', () => {
      expect(() => service.extractBearerToken('NotBearer token')).toThrow();
    });
  });
});
