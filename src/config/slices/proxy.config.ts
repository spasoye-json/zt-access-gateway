import type { ConfigService } from '@nestjs/config';

/**
 * Proxy + BOPLA slice (Phase 8 D-01, D-12).
 *
 * `serviceRegistry` is the raw JSON string; ServiceRegistryService parses
 * it at module init. Circuit breaker tuned via opossum thresholds.
 */
export interface ProxyConfig {
  /** JSON string mapping serviceName → baseUrl. Required (D-03/D-04). */
  readonly serviceRegistry: string;
  /** opossum volumeThreshold — min requests before tripping (default 5, D-12). */
  readonly cbVolumeThreshold: number;
  /** opossum errorThresholdPercentage — % failure rate to open (default 50, D-12). */
  readonly cbErrorThreshold: number;
  /** opossum resetTimeout — ms OPEN before HALF-OPEN probe (default 10000, D-12). */
  readonly cbResetTimeout: number;
  /** Max retries inside opossum action function (default 3, D-12). */
  readonly maxRetries: number;
  /** Path to BOPLA field policy JSON (default 'policy/field-policy.json', D-05). */
  readonly boplaPolicyPath: string;
}

export const PROXY_CONFIG = Symbol('PROXY_CONFIG');

export function buildProxyConfig(env: ConfigService): ProxyConfig {
  return Object.freeze({
    serviceRegistry: env.get<string>('PROXY_SERVICE_REGISTRY')!,
    cbVolumeThreshold: env.get<number>('PROXY_CB_VOLUME_THRESHOLD')!,
    cbErrorThreshold: env.get<number>('PROXY_CB_ERROR_THRESHOLD')!,
    cbResetTimeout: env.get<number>('PROXY_CB_RESET_TIMEOUT')!,
    maxRetries: env.get<number>('PROXY_MAX_RETRIES')!,
    boplaPolicyPath: env.get<string>('BOPLA_POLICY_PATH')!,
  });
}
