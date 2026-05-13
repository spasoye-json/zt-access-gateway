import {
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  OnModuleInit,
  ServiceUnavailableException,
} from '@nestjs/common';
import axios from 'axios';
import type { AxiosRequestConfig, AxiosResponse } from 'axios';
// opossum is a CJS module whose `module.exports` is the CircuitBreaker constructor
// (no `.default`); `tsconfig.json` has `esModuleInterop:false` so a default-import
// would not compile to a runtime-callable value. The TypeScript-native idiom for
// "import the whole CJS export as the binding" is `import = require(...)`.
// eslint-disable-next-line @typescript-eslint/no-require-imports
import CircuitBreaker = require('opossum');
import type { Request } from 'express';
import { PROXY_CONFIG, type ProxyConfig } from '../config/slices';
import { MtlsService } from '../shared/mtls.service';
import { sleep } from '../shared/sleep.util';
import type { UserClaims } from '../auth/interfaces/user-claims.interface';
import { ServiceRegistryService } from './service-registry.service';
import { DnsRebindingGuard } from './dns-rebinding.guard';
import { assertValidProxyResponse } from './response-validator';

/** D-10: retry only on these network error codes. */
const RETRIABLE_ERROR_CODES = new Set(['ECONNREFUSED', 'ETIMEDOUT', 'ECONNRESET']);
/** D-10: retry only on these gateway HTTP statuses (NOT 500/501 — Pitfall 3). */
const RETRIABLE_STATUSES = new Set([502, 503, 504]);
/** D-12: backoff schedule. */
const BACKOFF_DELAYS_MS = [100, 200, 400];

/** Headers stripped from outgoing proxy requests (PRXY-02). */
const STRIP_HEADERS = new Set([
  'authorization',
  'cookie',
  'x-forwarded-for',
  'host', // axios re-derives Host from the target URL — never forward inbound Host
  'content-length',
]);

@Injectable()
export class ProxyService implements OnModuleInit {
  private readonly logger = new Logger(ProxyService.name);
  private readonly breakers = new Map<
    string,
    CircuitBreaker<[AxiosRequestConfig], AxiosResponse>
  >();

  constructor(
    @Inject(PROXY_CONFIG) private readonly cfg: ProxyConfig,
    private readonly registry: ServiceRegistryService,
    private readonly dnsGuard: DnsRebindingGuard,
    private readonly mtls: MtlsService,
  ) {}

  onModuleInit(): void {
    // ServiceRegistryService.onModuleInit must run first (NestJS DI order).
    for (const serviceName of this.registry.listServices()) {
      const breaker = new CircuitBreaker(
        (config: AxiosRequestConfig) => this.executeWithRetry(config),
        {
          volumeThreshold: this.cfg.cbVolumeThreshold,
          errorThresholdPercentage: this.cfg.cbErrorThreshold,
          resetTimeout: this.cfg.cbResetTimeout,
          name: serviceName,
        },
      );
      breaker.on('open', () => this.logger.warn(`Circuit OPEN for service: ${serviceName}`));
      breaker.on('halfOpen', () =>
        this.logger.log(`Circuit HALF-OPEN for service: ${serviceName}`),
      );
      breaker.on('close', () => this.logger.log(`Circuit CLOSED for service: ${serviceName}`));
      this.breakers.set(serviceName, breaker);
    }
    this.logger.log(`ProxyService ready — ${this.breakers.size} circuit breaker(s) initialized`);
  }

  /**
   * Forward an authenticated request to the target downstream service.
   * Pipeline: registry resolve → DNS guard → opossum.fire → ResponseValidator → return AxiosResponse.
   * Caller (GatewayMiddleware) is responsible for BOPLA stripping and writing trust signals.
   */
  async forward(req: Request, claims: UserClaims, trustScore: number): Promise<AxiosResponse> {
    const serviceName = this.registry.extractServiceName(req.path);
    if (!serviceName) {
      throw new NotFoundException('Cannot extract service name from path');
    }
    const baseUrl = this.registry.resolve(serviceName); // throws NotFoundException for unknown services
    // Use req.url (pathname + query string) to preserve query params; strip only the path prefix.
    const parsed = new URL(req.url, 'http://placeholder');
    const strippedPathname = this.registry.stripPrefix(parsed.pathname);
    const forwardedPath = strippedPathname + parsed.search;

    const target = new URL(forwardedPath, baseUrl.endsWith('/') ? baseUrl : baseUrl + '/');
    await this.dnsGuard.assertSafe(target.hostname); // throws ForbiddenException

    const breaker = this.breakers.get(serviceName);
    if (!breaker) {
      // Defensive — onModuleInit guarantees one breaker per registered service
      throw new ServiceUnavailableException(`No circuit breaker for service: ${serviceName}`);
    }

    const httpsAgent = await this.mtls.getHttpsAgent();

    const axiosConfig: AxiosRequestConfig = {
      method: req.method,
      url: target.toString(),
      headers: this.buildProxyHeaders(req.headers, claims, trustScore),
      data: req.body as unknown,
      httpsAgent,
      // axios default responseType='json' — required for BOPLA (Pitfall 4); do NOT change
      validateStatus: () => true, // validate explicitly via assertValidProxyResponse
      timeout: 30000,
    };

    try {
      const response = await breaker.fire(axiosConfig);
      assertValidProxyResponse(response);
      return response;
    } catch (err) {
      // Narrow the catch binding (typed `unknown`) before passing to opossum's
      // `isOurError(err: Error)` — closes a no-unsafe-argument warning while
      // preserving the original control flow (non-Error throws fall through).
      if (err instanceof Error && CircuitBreaker.isOurError(err)) {
        throw new ServiceUnavailableException(`Circuit open for service: ${serviceName}`);
      }
      throw err;
    }
  }

  /**
   * Per D-11: opossum wraps the FULL retry loop. One fire() per request;
   * the breaker records ONE failure only after all retries are exhausted —
   * not one failure per attempt. Otherwise transient errors that resolve on
   * retry would prematurely trip the breaker.
   */
  private async executeWithRetry(config: AxiosRequestConfig): Promise<AxiosResponse> {
    const maxRetries = this.cfg.maxRetries; // default 3
    let lastErr: unknown;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const response = await axios(config);
        if (RETRIABLE_STATUSES.has(response.status)) {
          if (attempt < maxRetries) {
            await sleep(BACKOFF_DELAYS_MS[Math.min(attempt, BACKOFF_DELAYS_MS.length - 1)]);
            lastErr = new Error(`Upstream ${response.status}`);
            continue;
          }
          // Throw so opossum records a failure and can open the circuit.
          throw new Error(`Upstream ${response.status} after ${maxRetries} retries`);
        }
        return response; // success or non-retriable status (4xx / 500 / 501)
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        if (code && RETRIABLE_ERROR_CODES.has(code) && attempt < maxRetries) {
          await sleep(BACKOFF_DELAYS_MS[Math.min(attempt, BACKOFF_DELAYS_MS.length - 1)]);
          lastErr = err;
          continue;
        }
        throw err;
      }
    }
    throw lastErr ?? new Error('retry loop exhausted with no error captured');
  }

  private buildProxyHeaders(
    incoming: Record<string, string | string[] | undefined>,
    claims: UserClaims,
    trustScore: number,
  ): Record<string, string> {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(incoming)) {
      const lower = k.toLowerCase();
      if (STRIP_HEADERS.has(lower)) continue;
      if (lower.startsWith('x-gateway-')) continue; // strip incoming x-gateway-* per PRXY-02
      if (v === undefined) continue;
      out[k] = Array.isArray(v) ? v.join(', ') : String(v);
    }
    // Inject gateway context (PRXY-02)
    out['x-user-id'] = claims.userId;
    out['x-roles'] = (claims.roles ?? []).join(',');
    out['x-trust-score'] = String(trustScore);
    out['x-gateway-request'] = 'true';
    return out;
  }
}
