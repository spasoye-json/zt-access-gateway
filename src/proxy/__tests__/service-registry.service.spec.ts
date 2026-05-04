/**
 * Unit tests for ServiceRegistryService.
 * Covers: PRXY-03 (registry allowlist), PRXY-06 (unknown service rejected before I/O), D-04 (path-prefix routing).
 */
import { NotFoundException } from '@nestjs/common';
import { AppConfigService } from '../../config/config.service';
import { ServiceRegistryService } from '../service-registry.service';

function makeService(registryJson: string): ServiceRegistryService {
  const cfg = {
    proxyServiceRegistry: registryJson,
  } as unknown as AppConfigService;
  return new ServiceRegistryService(cfg);
}

describe('ServiceRegistryService', () => {
  describe('onModuleInit (PRXY-03)', () => {
    it('parses PROXY_SERVICE_REGISTRY JSON into Map<serviceName, baseUrl>', async () => {
      const svc = makeService(
        JSON.stringify({ users: 'https://users.internal:8443' }),
      );
      await svc.onModuleInit();
      expect(svc.resolve('users')).toBe('https://users.internal:8443');
    });

    it('throws Error when PROXY_SERVICE_REGISTRY is empty {}', async () => {
      const svc = makeService('{}');
      await expect(svc.onModuleInit()).rejects.toThrow(Error);
    });

    it('throws Error when PROXY_SERVICE_REGISTRY is malformed JSON', async () => {
      const svc = makeService('{"a":"b"');
      await expect(svc.onModuleInit()).rejects.toThrow(/JSON/i);
    });
  });

  describe('resolve(serviceName) (PRXY-06)', () => {
    let svc: ServiceRegistryService;

    beforeEach(async () => {
      svc = makeService(
        JSON.stringify({ users: 'https://users.internal:8443' }),
      );
      await svc.onModuleInit();
    });

    it('returns baseUrl when serviceName is in registry', () => {
      expect(svc.resolve('users')).toBe('https://users.internal:8443');
    });

    it('throws NotFoundException when serviceName is NOT in registry', () => {
      expect(() => svc.resolve('unknown')).toThrow(NotFoundException);
    });

    it('rejects before any DNS or network call', () => {
      // NotFoundException thrown synchronously — no I/O involved
      expect(() => svc.resolve('ghost')).toThrow(NotFoundException);
    });
  });

  describe('extractServiceName(path) (D-04 path-prefix routing)', () => {
    let svc: ServiceRegistryService;

    beforeEach(async () => {
      svc = makeService(
        JSON.stringify({ users: 'https://users.internal:8443' }),
      );
      await svc.onModuleInit();
    });

    it('returns first path segment for /users/profile → users', () => {
      expect(svc.extractServiceName('/users/profile')).toBe('users');
    });

    it('returns first path segment for /users/123/orders → users', () => {
      expect(svc.extractServiceName('/users/123/orders')).toBe('users');
    });

    it('returns null for empty path /', () => {
      expect(svc.extractServiceName('/')).toBeNull();
    });

    it('returns null for empty string', () => {
      expect(svc.extractServiceName('')).toBeNull();
    });
  });
});
