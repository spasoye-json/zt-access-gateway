import { Injectable, Logger, NotFoundException, OnModuleInit } from '@nestjs/common';
import { AppConfigService } from '../config/config.service';

@Injectable()
export class ServiceRegistryService implements OnModuleInit {
  private readonly logger = new Logger(ServiceRegistryService.name);
  private registry!: Map<string, string>;

  constructor(private readonly cfg: AppConfigService) {}

  async onModuleInit(): Promise<void> {
    let parsed: Record<string, string>;
    try {
      parsed = JSON.parse(this.cfg.proxyServiceRegistry);
    } catch (err) {
      throw new Error(
        `PROXY_SERVICE_REGISTRY is not valid JSON: ${(err as Error).message}`,
      );
    }
    if (!parsed || typeof parsed !== 'object' || Object.keys(parsed).length === 0) {
      throw new Error(
        'PROXY_SERVICE_REGISTRY is empty — at least one service must be configured (D-03)',
      );
    }
    this.registry = new Map(Object.entries(parsed));
    this.logger.log(
      `Service registry loaded: ${[...this.registry.keys()].join(', ')}`,
    );
  }

  /**
   * Resolves a service name to its baseUrl. Throws NotFoundException if missing.
   * Registry membership check happens before any I/O (PRXY-06).
   */
  resolve(serviceName: string): string {
    const url = this.registry.get(serviceName);
    if (!url) {
      throw new NotFoundException(
        `Unknown service: ${serviceName}. Not in PROXY_SERVICE_REGISTRY.`,
      );
    }
    return url;
  }

  /** Extracts first path segment per D-04. '/users/profile' → 'users'. */
  extractServiceName(path: string): string | null {
    if (!path || path === '/') return null;
    const stripped = path.startsWith('/') ? path.slice(1) : path;
    const first = stripped.split('/')[0];
    return first.length > 0 ? first : null;
  }

  /** Strips the service-name prefix and returns the forwarded path. '/users/profile' → '/profile'. */
  stripPrefix(path: string): string {
    const name = this.extractServiceName(path);
    if (!name) return path;
    const remainder = path.slice(`/${name}`.length);
    return remainder.length > 0 ? remainder : '/';
  }

  /** Returns registered service names (diagnostic accessor). */
  listServices(): string[] {
    return [...this.registry.keys()];
  }
}
