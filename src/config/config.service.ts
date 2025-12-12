import { Injectable } from '@nestjs/common';

@Injectable()
export class ConfigService {
  get(key: string): string | undefined {
    return process.env[key];
  }

  getNumber(key: string): number | undefined {
    const value = process.env[key];
    return value ? parseInt(value, 10) : undefined;
  }

  getBoolean(key: string): boolean {
    const value = process.env[key];
    return value === 'true' || value === '1';
  }

  // Gateway configuration
  getPort(): number {
    return this.getNumber('PORT') || 3000;
  }

  getJwtSecret(): string {
    return this.get('JWT_SECRET') || 'default_secret_for_development';
  }

  getTrustScoreThresholds(): { low: number; medium: number; high: number } {
    return {
      low: this.getNumber('TRUST_SCORE_LOW_THRESHOLD') || 0.3,
      medium: this.getNumber('TRUST_SCORE_MEDIUM_THRESHOLD') || 0.7,
      high: 1.0,
    };
  }

  // mTLS configuration
  getMtlsCaCertPath(): string | undefined {
    return this.get('MTLS_CA_CERT_PATH');
  }

  getMtlsCertPath(): string | undefined {
    return this.get('MTLS_CERT_PATH');
  }

  getMtlsKeyPath(): string | undefined {
    return this.get('MTLS_KEY_PATH');
  }

  // Security configuration
  getForceMtls(): boolean {
    return this.getBoolean('FORCE_MTLS');
  }

  getUseSecureConnections(): boolean {
    return this.getBoolean('USE_SECURE_CONNECTIONS');
  }

  getProxyMaxRetries(): number {
    return this.getNumber('PROXY_MAX_RETRIES') ?? 2;
  }

  getProxyRetryDelayMs(): number {
    return this.getNumber('PROXY_RETRY_DELAY_MS') ?? 100;
  }

  getProxyCircuitBreakerThreshold(): number {
    return this.getNumber('PROXY_CIRCUIT_BREAKER_THRESHOLD') ?? 3;
  }

  getProxyCircuitBreakerTimeoutMs(): number {
    return this.getNumber('PROXY_CIRCUIT_BREAKER_TIMEOUT_MS') ?? 30_000;
  }
}
