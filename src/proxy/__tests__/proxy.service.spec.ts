import { Test, TestingModule } from '@nestjs/testing';
import { HttpService } from '@nestjs/axios';
import { ProxyService } from '../proxy.service';
import { MtlsService } from '../../shared/mtls.service';
import { ConfigService } from '../../config/config.service';
import { ServiceRegistryService } from '../service-registry.service';
import { BadRequestException, ServiceUnavailableException } from '@nestjs/common';

describe('ProxyService', () => {
  let service: ProxyService;
  let mockMtlsService: Partial<MtlsService>;
  let mockConfigService: Partial<ConfigService>;
  let mockHttpService: Partial<HttpService>;
  let mockRegistry: Partial<ServiceRegistryService>;

  beforeEach(async () => {
    mockMtlsService = {
      createAgent: jest.fn().mockReturnValue({}),
    };

    mockConfigService = {
      getMtlsCaCertPath: jest.fn().mockReturnValue('./certs/ca.crt'),
      getMtlsCertPath: jest.fn().mockReturnValue('./certs/gateway.crt'),
      getMtlsKeyPath: jest.fn().mockReturnValue('./certs/gateway.key'),
      getProxyMaxRetries: jest.fn().mockReturnValue(0),
      getProxyRetryDelayMs: jest.fn().mockReturnValue(0),
      getProxyCircuitBreakerThreshold: jest.fn().mockReturnValue(3),
      getProxyCircuitBreakerTimeoutMs: jest.fn().mockReturnValue(1000),
    };

    // Mock axiosRef call
    mockHttpService = {
      axiosRef: jest.fn(),
    } as any;

    mockRegistry = {
      getServiceUrl: jest.fn().mockReturnValue('https://users-service:3001'),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ProxyService,
        { provide: MtlsService, useValue: mockMtlsService },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: HttpService, useValue: mockHttpService },
        { provide: ServiceRegistryService, useValue: mockRegistry },
      ],
    }).compile();

    service = module.get<ProxyService>(ProxyService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('forwardRequest', () => {
    it('should forward request with proper headers and return response', async () => {
      const mockResponse = {
        status: 200,
        data: { message: 'Success' },
        headers: { 'content-type': 'application/json' },
      };

      (mockHttpService.axiosRef as unknown as jest.Mock).mockResolvedValue(mockResponse);

      const result = await service.forwardRequest(
        'users-service',
        'GET',
        '/users',
        { authorization: 'Bearer token123' },
        null,
        {sessionId: "", userId: 'user123', roles: ['user'] },
        0.2
      );

      expect(result).toEqual({
        status: 200,
        data: { message: 'Success' },
        headers: { 'content-type': 'application/json' },
      });
      expect(mockHttpService.axiosRef).toHaveBeenCalled();
      expect(mockMtlsService.createAgent).toHaveBeenCalledWith('users-service');
    });

    it('should add user identity headers to forwarded request', async () => {
      const mockResponse = {
        status: 200,
        data: { message: 'Success' },
        headers: {},
      };

      (mockHttpService.axiosRef as unknown as jest.Mock).mockResolvedValue(mockResponse);

      await service.forwardRequest(
        'users-service',
        'GET',
        '/users',
        { 'x-custom': 'value' },
        null,
        {sessionId: "", userId: 'user123', roles: ['admin', 'user'] },
        0.5
      );

      expect(mockHttpService.axiosRef).toHaveBeenCalledWith(
        expect.objectContaining({
          headers: expect.objectContaining({
            'x-user-id': 'user123',
            'x-roles': 'admin,user',
            'x-trust-score': '0.5',
            'x-custom': 'value'
          }),
          httpsAgent: expect.any(Object),
        })
      );
    });

    it('should throw when service registry does not know target service', async () => {
      (mockRegistry.getServiceUrl as jest.Mock).mockReturnValue(null);

      await expect(
        service.forwardRequest('unknown-service', 'GET', '/users', {}, null, null, 0.2),
      ).rejects.toThrow(ServiceUnavailableException);
    });

    it('should propagate mTLS errors', async () => {
      (mockMtlsService.createAgent as jest.Mock).mockImplementation(() => {
        throw new ServiceUnavailableException('missing certs');
      });

      await expect(
        service.forwardRequest(
          'users-service',
          'GET',
          '/users',
          {},
          null,
          { sessionId: '', userId: 'user123', roles: [] },
          0.1,
        ),
      ).rejects.toThrow('missing certs');
    });

    it('should reject invalid paths', async () => {
      await expect(
        service.forwardRequest(
          'users-service',
          'GET',
          '/../etc/passwd',
          {},
          null,
          { sessionId: '', userId: 'user123', roles: [] },
          0.1,
        ),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject unsafe service URLs', async () => {
      (mockRegistry.getServiceUrl as jest.Mock).mockReturnValue('https://localhost:8443');

      await expect(
        service.forwardRequest(
          'users-service',
          'GET',
          '/users',
          {},
          null,
          { sessionId: '', userId: 'user123', roles: [] },
          0.1,
        ),
      ).rejects.toThrow(ServiceUnavailableException);
    });
  });
});
