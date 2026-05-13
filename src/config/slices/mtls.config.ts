import type { ConfigService } from '@nestjs/config';

/**
 * mTLS slice. Certificate paths + allowed CN allowlist for upstream
 * server certs. `allowedSubjects` is split from comma-separated env.
 */
export interface MtlsConfig {
  readonly caCertPath: string;
  readonly clientCertPath: string;
  readonly clientKeyPath: string;
  /** Comma-separated MTLS_ALLOWED_SUBJECTS exploded to readonly array. */
  readonly allowedSubjects: readonly string[];
}

export const MTLS_CONFIG = Symbol('MTLS_CONFIG');

export function buildMtlsConfig(env: ConfigService): MtlsConfig {
  return Object.freeze({
    caCertPath: env.get<string>('MTLS_CA_CERT_PATH')!,
    clientCertPath: env.get<string>('MTLS_CLIENT_CERT_PATH')!,
    clientKeyPath: env.get<string>('MTLS_CLIENT_KEY_PATH')!,
    allowedSubjects: Object.freeze(env.get<string>('MTLS_ALLOWED_SUBJECTS')!.split(',')),
  });
}
