import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/**
 * Typed wrapper over @nestjs/config ConfigService.
 * Only exposes Phase 1 env vars (CONF-03) — no stubs for future phases.
 */
@Injectable()
export class AppConfigService {
  constructor(private readonly config: ConfigService) {}

  get port(): number {
    return this.config.get<number>('PORT')!;
  }

  get nodeEnv(): string {
    return this.config.get<string>('NODE_ENV')!;
  }

  get corsOrigin(): string {
    return this.config.get<string>('CORS_ORIGIN')!;
  }

  get rateLimitWindowMs(): number {
    return this.config.get<number>('RATE_LIMIT_WINDOW_MS')!;
  }

  get rateLimitMax(): number {
    return this.config.get<number>('RATE_LIMIT_MAX')!;
  }

  get mtlsCaCertPath(): string {
    return this.config.get<string>('MTLS_CA_CERT_PATH')!;
  }

  get mtlsClientCertPath(): string {
    return this.config.get<string>('MTLS_CLIENT_CERT_PATH')!;
  }

  get mtlsClientKeyPath(): string {
    return this.config.get<string>('MTLS_CLIENT_KEY_PATH')!;
  }

  /** Returns comma-separated MTLS_ALLOWED_SUBJECTS as a string array. */
  get mtlsAllowedSubjects(): string[] {
    return this.config.get<string>('MTLS_ALLOWED_SUBJECTS')!.split(',');
  }
}
