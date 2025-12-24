import { Injectable, Logger, BadRequestException, ServiceUnavailableException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { MtlsService } from '../shared/mtls.service';
import { UserClaims } from '../auth/auth.service';
import { ConfigService } from '../config/config.service';
import { ServiceRegistryService } from './service-registry.service';

@Injectable()
export class ProxyService {
  private readonly logger = new Logger(ProxyService.name);
  private readonly circuitStates: Map<
    string,
    { failures: number; openUntil: number | null }
  > = new Map();

  constructor(
    private mtlsService: MtlsService,
    private configService: ConfigService,
    private httpService: HttpService,
    private serviceRegistry: ServiceRegistryService,
  ) {}

  async forwardRequest(
    targetService: string,
    method: string,
    path: string,
    headers: Record<string, string>,
    body: any,
    userClaims?: UserClaims,
    trustScore?: number,
  ): Promise<any> {
    this.logger.log(`Forwarding ${method} request to ${targetService}${path}`);

    try {
      // Validate input parameters
      if (!targetService || typeof targetService !== 'string') {
        throw new BadRequestException('Invalid target service specified');
      }

      if (!method || typeof method !== 'string' || !['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(method.toUpperCase())) {
        throw new BadRequestException('Invalid HTTP method');
      }

      if (!path || typeof path !== 'string') {
        throw new BadRequestException('Invalid path specified');
      }

      // Validate and sanitize path to prevent SSRF attacks
      if (!this.isValidPath(path)) {
        throw new BadRequestException('Invalid path detected');
      }

      // Add identity headers to the forwarded request
      const forwardedHeaders = { ...headers };
      delete forwardedHeaders['content-length'];
      delete forwardedHeaders['Content-Length'];
      delete forwardedHeaders['host'];
      delete forwardedHeaders['Host'];
      forwardedHeaders['x-gateway-request'] = 'true';
      if (userClaims) {
        forwardedHeaders['x-user-id'] = userClaims.userId;
        forwardedHeaders['x-roles'] = Array.isArray(userClaims.roles) ? userClaims.roles.join(',') : userClaims.roles || '';
      }
      if (trustScore !== undefined) {
        forwardedHeaders['x-trust-score'] = trustScore.toString();
      }

      // Determine target URL based on service
      const targetUrl = this.serviceRegistry.getServiceUrl(targetService);
      if (!targetUrl) {
        throw new ServiceUnavailableException(`Unknown target service: ${targetService}`);
      }

      const url = `${targetUrl}${path}`;

      // Validate URL to prevent SSRF
      const parsedUrl = new URL(url);
      if (!this.isSafeUrl(parsedUrl)) {
        throw new ServiceUnavailableException('Target URL is not safe');
      }

      const agent = this.mtlsService.createAgent(parsedUrl.hostname);

      // Make the actual mTLS request to the target service
      if (this.isCircuitOpen(targetService)) {
        throw new ServiceUnavailableException(
          `Circuit breaker open for ${targetService}. Please try again later.`,
        );
      }

      const response = await this.executeWithRetries(targetService, async () => {
        return this.httpService.axiosRef({
          method,
          url,
          headers: forwardedHeaders,
          data: body,
          httpsAgent: agent,
          timeout: 30000,
          validateStatus: (status) => status < 500,
        });
      });

      this.logger.log(`Successfully forwarded request to ${targetService}, received status: ${response.status}`);

      return {
        status: response.status,
        data: response.data,
        headers: response.headers,
      };
    } catch (error) {
      this.logger.error(`Error forwarding request to ${targetService}:`, error.message);

      if (error instanceof BadRequestException || error instanceof ServiceUnavailableException) {
        throw error;
      }

      if (error.code === 'ECONNREFUSED') {
        throw new ServiceUnavailableException(`Target service ${targetService} is unavailable`);
      } else if (error.code === 'ENOTFOUND') {
        throw new ServiceUnavailableException(`Target service ${targetService} not found`);
      } else if (error.code === 'ECONNABORTED') {
        throw new ServiceUnavailableException(`Request to ${targetService} timed out`);
      } else if (error.response) {
        // If the target service responded with an error
        return {
          status: error.response.status,
          data: error.response.data || { error: 'Service temporarily unavailable' },
          headers: error.response.headers,
        };
      } else {
        // If there was a connection error or other issue
        throw new ServiceUnavailableException(`Failed to forward request to ${targetService}: ${error.message}`);
      }
    }
  }

  private isValidPath(path: string): boolean {
    // Basic path validation to prevent path traversal attacks
    if (path.includes('../') || path.includes('..\\')) {
      return false;
    }

    // Prevent protocol schemes in path (potential SSRF)
    if (/^https?:\/\//.test(path)) {
      return false;
    }

    return true;
  }

  private isSafeUrl(url: URL): boolean {
    // Prevent internal network access to prevent SSRF
    const hostname = url.hostname.toLowerCase();

    // Block private IP ranges
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
  }

  private async executeWithRetries<T>(
    serviceName: string,
    fn: () => Promise<T>,
  ): Promise<T> {
    const maxRetries = this.configService.getProxyMaxRetries();
    const retryDelay = this.configService.getProxyRetryDelayMs();

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const result = await fn();
        this.resetCircuit(serviceName);
        return result;
      } catch (error) {
        const shouldRetry = attempt < maxRetries && this.isRetryableError(error);
        this.recordFailure(serviceName);

        if (!shouldRetry) {
          throw error;
        }

        const delayMs = retryDelay * (attempt + 1);
        this.logger.warn(
          `Retrying ${serviceName} after error (${error.message}). Attempt ${attempt + 1}/${maxRetries}`,
        );
        await this.delay(delayMs);
      }
    }

    throw new ServiceUnavailableException(`Failed to reach ${serviceName} after retries`);
  }

  private isRetryableError(error: any): boolean {
    if (!error) return false;
    const transientCodes = ['ECONNRESET', 'ECONNABORTED', 'ETIMEDOUT', 'EAI_AGAIN'];
    if (error.code && transientCodes.includes(error.code)) {
      return true;
    }
    if (error.response && error.response.status >= 500) {
      return true;
    }
    return false;
  }

  private recordFailure(serviceName: string) {
    const threshold = this.configService.getProxyCircuitBreakerThreshold();
    const timeoutMs = this.configService.getProxyCircuitBreakerTimeoutMs();
    const state = this.circuitStates.get(serviceName) || { failures: 0, openUntil: null };
    state.failures += 1;
    if (state.failures >= threshold) {
      state.openUntil = Date.now() + timeoutMs;
      this.logger.warn(`Circuit opened for ${serviceName} after ${state.failures} failures`);
    }
    this.circuitStates.set(serviceName, state);
  }

  private resetCircuit(serviceName: string) {
    const state = this.circuitStates.get(serviceName);
    if (state) {
      state.failures = 0;
      state.openUntil = null;
      this.circuitStates.set(serviceName, state);
    }
  }

  private isCircuitOpen(serviceName: string): boolean {
    const state = this.circuitStates.get(serviceName);
    if (!state || !state.openUntil) {
      return false;
    }
    if (Date.now() > state.openUntil) {
      this.resetCircuit(serviceName);
      return false;
    }
    return true;
  }

  private delay(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
