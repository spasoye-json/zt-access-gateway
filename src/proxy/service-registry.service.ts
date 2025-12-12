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

  constructor(private readonly configService: ConfigService) {
    const raw = this.configService.get<string>('SERVICE_REGISTRY');
    if (raw) {
      try {
        const entries = JSON.parse(raw) as Record<string, string>;
        for (const [name, url] of Object.entries(entries)) {
          this.services.set(name, url);
        }
      } catch (error) {
        this.logger.error(`Failed to parse SERVICE_REGISTRY env: ${error.message}`);
      }
    }

    if (this.services.size === 0) {
      this.logger.log('Using default service registry configuration');
      this.services.set('users-service', 'https://users-service:3001');
      this.services.set('orders-service', 'https://orders-service:3002');
      this.services.set('permissions-service', 'https://permissions-service:3003');
      this.services.set('default-service', 'https://default-service:3000');
    }
  }

  getServiceUrl(serviceName: string): string | null {
    return this.services.get(serviceName) ?? null;
  }

  registerService(serviceName: string, baseUrl: string) {
    this.services.set(serviceName, baseUrl);
  }
}

