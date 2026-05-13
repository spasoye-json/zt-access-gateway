import type { ConfigService } from '@nestjs/config';

/**
 * Server / runtime slice.
 *
 * Bootstrap-time knobs (port, CORS, rate-limit) plus cross-cutting infra
 * (databaseUrl, blacklistTtlMs, honeypotRoutes) that don't yet have their
 * own dedicated module. Phase B2 will pull databaseUrl out into DbModule.
 */
export interface ServerConfig {
  readonly port: number;
  readonly nodeEnv: string;
  readonly corsOrigin: string;
  readonly rateLimitWindowMs: number;
  readonly rateLimitMax: number;
  readonly databaseUrl: string;
  /** How long a blacklisted JA4H fingerprint stays blocked (ms). Default: 1 hour. */
  readonly blacklistTtlMs: number;
  /**
   * Additional honeypot routes from env (JSON array string).
   * Empty array if unset or unparseable. Hardcoded defaults in HoneypotModule always apply.
   */
  readonly honeypotRoutes: readonly string[];
}

export const SERVER_CONFIG = Symbol('SERVER_CONFIG');

function parseHoneypotRoutes(raw: string | undefined): readonly string[] {
  if (!raw) return Object.freeze([]);
  try {
    const parsed = JSON.parse(raw) as string[];
    return Object.freeze(Array.isArray(parsed) ? parsed : []);
  } catch {
    return Object.freeze([]);
  }
}

export function buildServerConfig(env: ConfigService): ServerConfig {
  return Object.freeze({
    port: env.get<number>('PORT')!,
    nodeEnv: env.get<string>('NODE_ENV')!,
    corsOrigin: env.get<string>('CORS_ORIGIN')!,
    rateLimitWindowMs: env.get<number>('RATE_LIMIT_WINDOW_MS')!,
    rateLimitMax: env.get<number>('RATE_LIMIT_MAX')!,
    databaseUrl: env.get<string>('DATABASE_URL')!,
    blacklistTtlMs: env.get<number>('BLACKLIST_TTL_MS')!,
    honeypotRoutes: parseHoneypotRoutes(env.get<string>('HONEYPOT_ROUTES')),
  });
}
