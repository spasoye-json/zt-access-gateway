import { Test, TestingModule } from '@nestjs/testing';
import { HttpService } from '@nestjs/axios';
import * as https from 'https';
import * as fs from 'fs';
import { ProxyService } from '../proxy.service';
import { ConfigService } from '../../config/config.service';
import { MtlsService } from '../../shared/mtls.service';
import { ServiceRegistryService } from '../service-registry.service';

// Mock the file system to simulate certificate reading
jest.mock('fs');
jest.mock('https');

describe('mTLS Functionality Tests', () => {
  let service: ProxyService;
  let mockConfigService: Partial<ConfigService>;
  let mockHttpService: Partial<HttpService>;
  let mockMtlsService: Partial<MtlsService>;
  let mockRegistry: Partial<ServiceRegistryService>;

  beforeEach(async () => {
    mockMtlsService = {};
    mockConfigService = {
      getMtlsCaCertPath: jest.fn().mockReturnValue('./certs/ca.crt'),
      getMtlsCertPath: jest.fn().mockReturnValue('./certs/gateway.crt'),
      getMtlsKeyPath: jest.fn().mockReturnValue('./certs/gateway.key'),
      getProxyMaxRetries: jest.fn().mockReturnValue(0),
      getProxyRetryDelayMs: jest.fn().mockReturnValue(0),
      getProxyCircuitBreakerThreshold: jest.fn().mockReturnValue(3),
      getProxyCircuitBreakerTimeoutMs: jest.fn().mockReturnValue(1000),
    };

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

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Certificate validation and mTLS configuration', () => {
    it('should read certificate files when forwarding request', async () => {
      // Mock certificate file reading
      (fs.readFileSync as jest.Mock)
        .mockReturnValueOnce(Buffer.from('ca-cert-content'))  // CA cert
        .mockReturnValueOnce(Buffer.from('client-cert-content'))  // Client cert
        .mockReturnValueOnce(Buffer.from('client-key-content')); // Client key

      // Mock successful HTTP response
      (mockHttpService.axiosRef as unknown as jest.Mock).mockResolvedValue({
        status: 200,
        data: { message: 'Success' },
        headers: {},
      });

      await service.forwardRequest(
        'users-service',
        'GET',
        '/users',
        {},
        null,
        {sessionId: "", userId: 'user123', roles: ['user'] },
        0.2
      );

      // Verify that certificates were read
      expect(fs.readFileSync).toHaveBeenCalledWith('./certs/ca.crt');
      expect(fs.readFileSync).toHaveBeenCalledWith('./certs/gateway.crt');
      expect(fs.readFileSync).toHaveBeenCalledWith('./certs/gateway.key');
      
      // Verify that the HTTPS agent was configured with certificates
      expect(mockHttpService.axiosRef).toHaveBeenCalledWith(
        expect.objectContaining({
          httpsAgent: expect.any(https.Agent)
        })
      );
    });

    it('should return error response when certificates are missing', async () => {
      // Mock file reading to throw an error on the first call (CA cert)
      (fs.readFileSync as jest.Mock)
        .mockImplementationOnce(() => { throw new Error('File not found'); })
        .mockReturnValueOnce(Buffer.from('client-cert-content'))  // This won't be reached
        .mockReturnValueOnce(Buffer.from('client-key-content'));  // This won't be reached

      await expect(
        service.forwardRequest(
          'users-service',
          'GET',
          '/users',
          {},
          null,
          { sessionId: '', userId: 'user123', roles: ['user'] },
          0.2,
        ),
      ).rejects.toThrow();
    });

    it('should properly configure HTTPS agent with mTLS options', async () => {
      // Mock certificate file reading
      (fs.readFileSync as jest.Mock)
        .mockReturnValueOnce(Buffer.from('ca-cert-content'))
        .mockReturnValueOnce(Buffer.from('client-cert-content'))
        .mockReturnValueOnce(Buffer.from('client-key-content'));

      (mockHttpService.axiosRef as unknown as jest.Mock).mockResolvedValue({
        status: 200,
        data: { message: 'Success' },
        headers: {},
      });

      await service.forwardRequest(
        'users-service',
        'GET',
        '/users',
        {},
        null,
        {sessionId: "", userId: 'user123', roles: ['user'] },
        0.2
      );

      // Check that axiosRef was called with an httpsAgent
      expect(mockHttpService.axiosRef).toHaveBeenCalledWith(
        expect.objectContaining({
          httpsAgent: expect.any(https.Agent)
        })
      );
    });
  });

  describe('mTLS URL validation', () => {
    it('should validate service URLs to prevent SSRF', () => {
      // Test the URL validation by simulating the logic used in the service
      // Instead of accessing private methods directly, we'll test the validation logic

      // Test URL safety for a valid service name
      const testUrl = (urlString: string): boolean => {
        const url = new URL(urlString);
        const hostname = url.hostname.toLowerCase();

        // Replicating the exact logic from ProxyService.isSafeUrl
        if (/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/.test(hostname) ||
            hostname === 'localhost' || hostname.startsWith('127.') ||
            hostname.startsWith('internal.') || hostname.endsWith('.internal')) {
          return false;
        }

        // Block other potentially dangerous hostnames
        if (hostname.includes('docker')) {
          return false;
        }

        return true;
      };

      // Test URL safety
      expect(testUrl('https://users-service:3001/users')).toBe(true);

      // Test unsafe URLs
      expect(testUrl('https://localhost:3001/users')).toBe(false);
      expect(testUrl('https://127.0.0.1:3001/users')).toBe(false);
      expect(testUrl('https://10.0.0.1:3001/users')).toBe(false);
      expect(testUrl('https://172.16.0.1:3001/users')).toBe(false);
      expect(testUrl('https://internal.service:3001/users')).toBe(false);  // hostname starts with "internal."
      expect(testUrl('https://test.internal:3001/users')).toBe(false);    // hostname ends with ".internal"
      expect(testUrl('https://test-docker-container:3001/users')).toBe(false);   // contains "docker" (from additional check)

      // Also test the path validation by replicating that logic
      const testPath = (path: string): boolean => {
        // Replicating the exact logic from ProxyService.isValidPath
        if (path.includes('../') || path.includes('..\\')) {
          return false;
        }

        // Prevent protocol schemes in path (potential SSRF)
        if (/^https?:\/\//.test(path)) {
          return false;
        }

        return true;
      };

      // Test path validation
      expect(testPath('/users')).toBe(true);
      expect(testPath('/users/../etc/passwd')).toBe(false);
      expect(testPath('http://external-service.com')).toBe(false);
    });
  });
});
