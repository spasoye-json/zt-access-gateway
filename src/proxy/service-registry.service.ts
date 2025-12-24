import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export interface ServiceConfig {
  name: string;
  baseUrl: string;
}

@Injectable()
export class ServiceRegistryService {
  private readonly logger = new Logger(ServiceRegistryService.name);
  private readonly services: Map<string, string> = new Map();
  private readonly allowedHosts: Set<string> = new Set();

  constructor(private readonly configService: ConfigService) {
    const raw = this.configService.get<string>('SERVICE_REGISTRY');
    if (raw) {
      try {
        const entries = JSON.parse(raw) as Record<string, string>;
        for (const [name, url] of Object.entries(entries)) {
          this.registerService(name, url);
        }
      } catch (error) {
        this.logger.error(`Failed to parse SERVICE_REGISTRY env: ${error.message}`);
      }
    }

    if (this.services.size === 0) {
      this.logger.log('Using default service registry configuration');
      this.registerService('users-service', 'https://users-service:3001');
      this.registerService('orders-service', 'https://orders-service:3002');
      this.registerService('permissions-service', 'https://permissions-service:3003');
      this.registerService('default-service', 'https://default-service:3000');
    }
  }

  getServiceUrl(serviceName: string): string | null {
    return this.services.get(serviceName) ?? null;
  }

  isAllowedTarget(url: URL): boolean {
    return this.allowedHosts.has(url.hostname.toLowerCase());
  }

  registerService(serviceName: string, baseUrl: string) {
    const normalized = this.normalizeUrl(baseUrl, serviceName);
    if (!normalized) {
      return;
    }
    this.services.set(serviceName, normalized);
  }

  private normalizeUrl(baseUrl: string, serviceName: string): string | null {
    try {
      const parsed = new URL(baseUrl);
      if (!parsed.hostname) {
        throw new Error('Missing hostname');
      }
      this.allowedHosts.add(parsed.hostname.toLowerCase());
      return parsed.toString().replace(/\/$/, '');
    } catch (error) {
      this.logger.error(`Invalid service URL for ${serviceName}: ${baseUrl}`);
      return null;
    }
  }
}
