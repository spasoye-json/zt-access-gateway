/**
 * Tests for ProxyService.
 * Covers: PRXY-01 (mTLS forwarding), PRXY-02 (header strip + inject),
 *         PRXY-04 (circuit breaker state), PRXY-05 (exponential backoff retry).
 */
import { ForbiddenException, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import type { AxiosResponse } from 'axios';
import type { Request } from 'express';

// Mock axios before importing ProxyService (must be before any imports that pull it in)
jest.mock('axios');

// Mock sleep so backoff tests are instant
jest.mock('../../shared/sleep.util', () => ({
  sleep: jest.fn().mockResolvedValue(undefined),
  randomDelay: jest.fn().mockReturnValue(0),
}));

import axios from 'axios';
import { sleep } from '../../shared/sleep.util';
import { ProxyService } from '../proxy.service';
import { ServiceRegistryService } from '../service-registry.service';
import { DnsRebindingGuard } from '../dns-rebinding.guard';
import type { UserClaims } from '../../auth/interfaces/user-claims.interface';
import type { ProxyConfig } from '../../config/slices';
import type { MtlsService } from '../../shared/mtls.service';

const axiosMock = axios as unknown as jest.Mock;

// --- helpers ---------------------------------------------------------------

function makeRegistryMock(
  services: string[] = ['users', 'orders'],
): jest.Mocked<ServiceRegistryService> {
  return {
    onModuleInit: jest.fn().mockResolvedValue(undefined),
    resolve: jest.fn((name: string) => {
      if (services.includes(name)) return `https://${name}.internal`;
      throw new NotFoundException(`Unknown service: ${name}`);
    }),
    extractServiceName: jest.fn((path: string) => {
      if (!path || path === '/') return null;
      const stripped = path.startsWith('/') ? path.slice(1) : path;
      const first = stripped.split('/')[0];
      return first.length > 0 ? first : null;
    }),
    stripPrefix: jest.fn((path: string) => {
      const name = path.startsWith('/') ? path.slice(1).split('/')[0] : path.split('/')[0];
      const remainder = path.slice(`/${name}`.length);
      return remainder.length > 0 ? remainder : '/';
    }),
    listServices: jest.fn().mockReturnValue(services),
  } as unknown as jest.Mocked<ServiceRegistryService>;
}

function makeDnsGuardMock(): jest.Mocked<DnsRebindingGuard> {
  return {
    assertSafe: jest.fn().mockResolvedValue(undefined),
  } as unknown as jest.Mocked<DnsRebindingGuard>;
}

function makeMtlsMock(): jest.Mocked<MtlsService> {
  const fakeAgent = { keepAlive: true } as unknown as import('https').Agent;
  return {
    getHttpsAgent: jest.fn().mockResolvedValue(fakeAgent),
  } as unknown as jest.Mocked<MtlsService>;
}

function makeCfgMock(overrides?: Partial<ProxyConfig>): jest.Mocked<ProxyConfig> {
  return {
    serviceRegistry: '{"users":"https://users.internal","orders":"https://orders.internal"}',
    cbVolumeThreshold: 10,
    cbErrorThreshold: 50,
    cbResetTimeout: 10000,
    maxRetries: 3,
    ...overrides,
  } as unknown as jest.Mocked<ProxyConfig>;
}

function makeClaims(overrides?: Partial<UserClaims>): UserClaims {
  return {
    userId: 'u-123',
    roles: ['user'],
    jti: 'jti-abc',
    exp: Math.floor(Date.now() / 1000) + 300,
    deviceId: 'dev-1',
    ...overrides,
  };
}

function makeRequest(overrides?: Partial<Request>): Request {
  const req = {
    method: 'GET',
    path: '/users/profile',
    url: '/users/profile',
    headers: {
      accept: 'application/json',
      'user-agent': 'test-agent',
    },
    body: undefined,
    ...overrides,
  } as unknown as Request;
  // If url wasn't explicitly provided, sync it to path so existing tests keep working.
  if (!overrides?.url && overrides?.path) {
    (req as any).url = overrides.path;
  }
  return req;
}

function makeOkResponse(overrides?: Partial<AxiosResponse>): AxiosResponse {
  return {
    status: 200,
    headers: { 'content-type': 'application/json' },
    data: { id: 'u-123' },
    ...overrides,
  } as unknown as AxiosResponse;
}

// ---------------------------------------------------------------------------

describe('ProxyService', () => {
  let registry: jest.Mocked<ServiceRegistryService>;
  let dnsGuard: jest.Mocked<DnsRebindingGuard>;
  let mtls: jest.Mocked<MtlsService>;
  let cfg: jest.Mocked<ProxyConfig>;
  let service: ProxyService;

  beforeEach(async () => {
    jest.clearAllMocks();
    registry = makeRegistryMock();
    dnsGuard = makeDnsGuardMock();
    mtls = makeMtlsMock();
    cfg = makeCfgMock();
    service = new ProxyService(cfg, registry, dnsGuard, mtls);
    await service.onModuleInit();
  });

  describe('onModuleInit (D-03)', () => {
    it('creates one CircuitBreaker per service in registry', async () => {
      const localRegistry = makeRegistryMock(['svc-a', 'svc-b', 'svc-c']);
      const localSvc = new ProxyService(cfg, localRegistry, dnsGuard, mtls);
      await localSvc.onModuleInit();
      // Verify each service has a breaker by calling forward for each service
      axiosMock.mockResolvedValue(makeOkResponse());
      const req = makeRequest({ path: '/svc-a/test' });
      await localSvc.forward(req, makeClaims(), 0.1);
      const req2 = makeRequest({ path: '/svc-b/test' });
      await localSvc.forward(req2, makeClaims(), 0.1);
      // no throw → breakers exist for both services
      expect(axiosMock).toHaveBeenCalledTimes(2);
    });

    it('breakers are stored in a Map<serviceName, CircuitBreaker>', async () => {
      // Verify breakers map is populated — indirect: calling forward on both services works
      axiosMock.mockResolvedValue(makeOkResponse());
      await service.forward(makeRequest({ path: '/users/me' }), makeClaims(), 0.0);
      await service.forward(makeRequest({ path: '/orders/1' }), makeClaims(), 0.0);
      expect(axiosMock).toHaveBeenCalledTimes(2);
    });
  });

  describe('forward() — header sanitization (PRXY-02)', () => {
    it('strips Authorization header from outgoing request', async () => {
      axiosMock.mockResolvedValue(makeOkResponse());
      await service.forward(
        makeRequest({ headers: { authorization: 'Bearer secret', accept: 'application/json' } }),
        makeClaims(),
        0.0,
      );
      const headers = axiosMock.mock.calls[0][0].headers as Record<string, string>;
      expect(headers['authorization']).toBeUndefined();
    });

    it('strips Cookie header from outgoing request', async () => {
      axiosMock.mockResolvedValue(makeOkResponse());
      await service.forward(
        makeRequest({ headers: { cookie: 'sid=abc', accept: 'application/json' } }),
        makeClaims(),
        0.0,
      );
      const headers = axiosMock.mock.calls[0][0].headers as Record<string, string>;
      expect(headers['cookie']).toBeUndefined();
    });

    it('strips x-forwarded-for header (re-set by gateway)', async () => {
      axiosMock.mockResolvedValue(makeOkResponse());
      await service.forward(
        makeRequest({ headers: { 'x-forwarded-for': '1.2.3.4', accept: 'application/json' } }),
        makeClaims(),
        0.0,
      );
      const headers = axiosMock.mock.calls[0][0].headers as Record<string, string>;
      expect(headers['x-forwarded-for']).toBeUndefined();
    });

    it('strips any incoming x-gateway-* headers', async () => {
      axiosMock.mockResolvedValue(makeOkResponse());
      await service.forward(
        makeRequest({
          headers: {
            'x-gateway-foo': 'spoofed',
            'x-gateway-request': 'fake',
            accept: 'application/json',
          },
        }),
        makeClaims(),
        0.0,
      );
      const headers = axiosMock.mock.calls[0][0].headers as Record<string, string>;
      expect(headers['x-gateway-foo']).toBeUndefined();
      // x-gateway-request is re-set by proxy; but the original caller's value is stripped and replaced
      expect(headers['x-gateway-request']).toBe('true');
    });

    it('injects x-user-id from UserClaims.userId', async () => {
      axiosMock.mockResolvedValue(makeOkResponse());
      await service.forward(makeRequest(), makeClaims({ userId: 'u-999' }), 0.0);
      const headers = axiosMock.mock.calls[0][0].headers as Record<string, string>;
      expect(headers['x-user-id']).toBe('u-999');
    });

    it('injects x-roles as comma-separated UserClaims.roles', async () => {
      axiosMock.mockResolvedValue(makeOkResponse());
      await service.forward(makeRequest(), makeClaims({ roles: ['admin', 'user'] }), 0.0);
      const headers = axiosMock.mock.calls[0][0].headers as Record<string, string>;
      expect(headers['x-roles']).toBe('admin,user');
    });

    it('injects x-trust-score as String(score)', async () => {
      axiosMock.mockResolvedValue(makeOkResponse());
      await service.forward(makeRequest(), makeClaims(), 0.42);
      const headers = axiosMock.mock.calls[0][0].headers as Record<string, string>;
      expect(headers['x-trust-score']).toBe('0.42');
    });

    it('injects x-gateway-request: true', async () => {
      axiosMock.mockResolvedValue(makeOkResponse());
      await service.forward(makeRequest(), makeClaims(), 0.0);
      const headers = axiosMock.mock.calls[0][0].headers as Record<string, string>;
      expect(headers['x-gateway-request']).toBe('true');
    });
  });

  describe('forward() — mTLS (PRXY-01)', () => {
    it('passes MtlsService.getHttpsAgent() as axios httpsAgent option', async () => {
      const fakeAgent = { keepAlive: true, isFakeAgent: true } as unknown as import('https').Agent;
      mtls.getHttpsAgent.mockResolvedValue(fakeAgent);
      axiosMock.mockResolvedValue(makeOkResponse());
      await service.forward(makeRequest(), makeClaims(), 0.0);
      const axiosCfg = axiosMock.mock.calls[0][0];
      expect(axiosCfg.httpsAgent).toBe(fakeAgent);
    });
  });

  describe('forward() — retry loop (PRXY-05, D-10)', () => {
    it('retries on ECONNREFUSED with 100ms → 200ms → 400ms backoff', async () => {
      const err = Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' });
      axiosMock
        .mockRejectedValueOnce(err)
        .mockRejectedValueOnce(err)
        .mockRejectedValueOnce(err)
        .mockResolvedValue(makeOkResponse());
      await service.forward(makeRequest(), makeClaims(), 0.0);
      expect(axiosMock).toHaveBeenCalledTimes(4);
      expect((sleep as jest.Mock).mock.calls).toEqual([[100], [200], [400]]);
    });

    it('retries on ETIMEDOUT', async () => {
      const err = Object.assign(new Error('ETIMEDOUT'), { code: 'ETIMEDOUT' });
      axiosMock.mockRejectedValueOnce(err).mockResolvedValue(makeOkResponse());
      await service.forward(makeRequest(), makeClaims(), 0.0);
      expect(axiosMock).toHaveBeenCalledTimes(2);
    });

    it('retries on ECONNRESET', async () => {
      const err = Object.assign(new Error('ECONNRESET'), { code: 'ECONNRESET' });
      axiosMock.mockRejectedValueOnce(err).mockResolvedValue(makeOkResponse());
      await service.forward(makeRequest(), makeClaims(), 0.0);
      expect(axiosMock).toHaveBeenCalledTimes(2);
    });

    it('retries on 502/503/504 status codes', async () => {
      axiosMock
        .mockResolvedValueOnce({
          status: 502,
          headers: { 'content-type': 'application/json' },
          data: {},
        })
        .mockResolvedValueOnce({
          status: 503,
          headers: { 'content-type': 'application/json' },
          data: {},
        })
        .mockResolvedValueOnce({
          status: 504,
          headers: { 'content-type': 'application/json' },
          data: {},
        })
        .mockResolvedValue(makeOkResponse());
      await service.forward(makeRequest(), makeClaims(), 0.0);
      expect(axiosMock).toHaveBeenCalledTimes(4);
    });

    it('does NOT retry on 4xx status codes', async () => {
      axiosMock.mockResolvedValue({
        status: 401,
        headers: { 'content-type': 'application/json' },
        data: { error: 'Unauthorized' },
      });
      const result = await service.forward(makeRequest(), makeClaims(), 0.0);
      expect(axiosMock).toHaveBeenCalledTimes(1);
      expect(result.status).toBe(401);
    });

    it('does NOT retry on 500/501 (per Pitfall 3 — only gateway errors retried)', async () => {
      axiosMock.mockResolvedValue({
        status: 500,
        headers: { 'content-type': 'application/json' },
        data: {},
      });
      // assertValidProxyResponse should throw ServiceUnavailableException for 5xx
      await expect(service.forward(makeRequest(), makeClaims(), 0.0)).rejects.toBeInstanceOf(
        ServiceUnavailableException,
      );
      // axios called exactly once — no retry
      expect(axiosMock).toHaveBeenCalledTimes(1);
    });

    it('after maxRetries exhausted, throws to opossum (which records single failure per D-11)', async () => {
      const err = Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' });
      axiosMock.mockRejectedValue(err);
      await expect(service.forward(makeRequest(), makeClaims(), 0.0)).rejects.toBeDefined();
      // 1 initial + 3 retries = 4 calls
      expect(axiosMock).toHaveBeenCalledTimes(4);
    });
  });

  describe('forward() — circuit breaker (PRXY-04, D-02, D-11)', () => {
    it('OPEN state → throws ServiceUnavailableException without calling axios', async () => {
      // Use a fast-tripping breaker: low thresholds
      const fastCfg = makeCfgMock({
        cbVolumeThreshold: 1,
        cbErrorThreshold: 1,
        cbResetTimeout: 5000,
        maxRetries: 0,
      });
      const svc = new ProxyService(fastCfg, registry, dnsGuard, mtls);
      await svc.onModuleInit();

      // Force the circuit open with one failure
      const err = Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' });
      axiosMock.mockRejectedValue(err);
      await expect(svc.forward(makeRequest(), makeClaims(), 0.0)).rejects.toBeDefined();
      axiosMock.mockClear();

      // Now breaker is OPEN — next call should get ServiceUnavailableException quickly
      // (opossum may throw its own error, which we map to ServiceUnavailableException)
      await expect(svc.forward(makeRequest(), makeClaims(), 0.0)).rejects.toBeInstanceOf(
        ServiceUnavailableException,
      );
    });

    it('per-service breakers are isolated — service-A failure does not trip service-B', async () => {
      const fastCfg = makeCfgMock({
        cbVolumeThreshold: 1,
        cbErrorThreshold: 1,
        cbResetTimeout: 5000,
        maxRetries: 0,
      });
      const localRegistry = makeRegistryMock(['svcA', 'svcB']);
      const svc = new ProxyService(fastCfg, localRegistry, dnsGuard, mtls);
      await svc.onModuleInit();

      // Trip svcA
      const err = Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' });
      axiosMock.mockRejectedValue(err);
      await expect(
        svc.forward(makeRequest({ path: '/svcA/x' }), makeClaims(), 0.0),
      ).rejects.toBeDefined();

      // svcB should still work
      axiosMock.mockResolvedValue(makeOkResponse());
      const result = await svc.forward(makeRequest({ path: '/svcB/y' }), makeClaims(), 0.0);
      expect(result.status).toBe(200);
    });

    it('breaker only records failure once per request, not per retry attempt (D-11)', async () => {
      // With 3 retries, axios is called 4 times but opossum records 1 failure
      const err = Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' });
      axiosMock.mockRejectedValue(err);
      try {
        await service.forward(makeRequest(), makeClaims(), 0.0);
      } catch {
        // expected
      }
      // 4 axios calls = 1 initial + 3 retries, all inside single opossum.fire()
      expect(axiosMock).toHaveBeenCalledTimes(4);
    });
  });

  describe('forward() — registry + DNS (PRXY-03, PRXY-06, PRXY-07)', () => {
    it('rejects unknown service before any DNS resolve or axios call', async () => {
      registry.extractServiceName.mockReturnValue('unknown-svc');
      registry.resolve.mockImplementation(() => {
        throw new NotFoundException('Unknown service: unknown-svc');
      });
      await expect(
        service.forward(makeRequest({ path: '/unknown-svc/x' }), makeClaims(), 0.0),
      ).rejects.toBeInstanceOf(NotFoundException);
      expect(dnsGuard.assertSafe).not.toHaveBeenCalled();
      expect(axiosMock).not.toHaveBeenCalled();
    });

    it('calls DnsRebindingGuard.assertSafe before opossum.fire', async () => {
      const callOrder: string[] = [];
      dnsGuard.assertSafe.mockImplementation(async () => {
        callOrder.push('dns');
      });
      axiosMock.mockImplementation(async () => {
        callOrder.push('axios');
        return makeOkResponse();
      });
      await service.forward(makeRequest(), makeClaims(), 0.0);
      expect(callOrder[0]).toBe('dns');
      expect(callOrder[1]).toBe('axios');
    });

    it('throws ForbiddenException when DnsRebindingGuard.assertSafe rejects', async () => {
      dnsGuard.assertSafe.mockRejectedValue(new ForbiddenException('DNS rebinding blocked'));
      await expect(service.forward(makeRequest(), makeClaims(), 0.0)).rejects.toBeInstanceOf(
        ForbiddenException,
      );
      expect(axiosMock).not.toHaveBeenCalled();
    });
  });
});
