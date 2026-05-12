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
    return this.config.get<number>('PORT');
  }

  get nodeEnv(): string {
    return this.config.get<string>('NODE_ENV');
  }

  get corsOrigin(): string {
    return this.config.get<string>('CORS_ORIGIN');
  }

  get rateLimitWindowMs(): number {
    return this.config.get<number>('RATE_LIMIT_WINDOW_MS');
  }

  get rateLimitMax(): number {
    return this.config.get<number>('RATE_LIMIT_MAX');
  }

  get mtlsCaCertPath(): string {
    return this.config.get<string>('MTLS_CA_CERT_PATH');
  }

  get mtlsClientCertPath(): string {
    return this.config.get<string>('MTLS_CLIENT_CERT_PATH');
  }

  get mtlsClientKeyPath(): string {
    return this.config.get<string>('MTLS_CLIENT_KEY_PATH');
  }

  /** Returns comma-separated MTLS_ALLOWED_SUBJECTS as a string array. */
  get mtlsAllowedSubjects(): string[] {
    return this.config.get<string>('MTLS_ALLOWED_SUBJECTS').split(',');
  }

  /** How long a blacklisted JA4H fingerprint stays blocked (ms). Default: 1 hour. */
  get blacklistTtlMs(): number {
    return this.config.get<number>('BLACKLIST_TTL_MS');
  }

  /**
   * Additional honeypot routes from env (JSON array string).
   * Returns empty array if unset or unparseable. Hardcoded defaults in HoneypotModule always apply.
   */
  get honeypotRoutes(): string[] {
    const raw = this.config.get<string>('HONEYPOT_ROUTES');
    if (!raw) return [];
    try {
      return JSON.parse(raw) as string[];
    } catch {
      return [];
    }
  }

  // --- Phase 3: JWT Auth (D-11) ---

  /** HS256 signing/verification secret. Required. Min 32 chars. */
  get jwtSecret(): string {
    return this.config.get<string>('JWT_SECRET');
  }

  /** PEM-encoded SPKI public key for RS256/ES256. Optional. */
  get jwtPublicKey(): string | undefined {
    return this.config.get<string>('JWT_PUBLIC_KEY');
  }

  /** Remote JWKS endpoint URL. Optional. Used when JWT_PUBLIC_KEY not set. */
  get jwksUri(): string | undefined {
    return this.config.get<string>('JWKS_URI');
  }

  /** Expected JWT issuer claim. Optional -- skips iss validation when unset. */
  get jwtIssuer(): string | undefined {
    return this.config.get<string>('JWT_ISSUER');
  }

  /** Expected JWT audience claim. Optional -- skips aud validation when unset. */
  get jwtAudience(): string | undefined {
    return this.config.get<string>('JWT_AUDIENCE');
  }

  // --- Phase 4: Trust score + telemetry (D-21) ---

  get databaseUrl(): string {
    return this.config.get<string>('DATABASE_URL');
  }

  get trustKnownThreshold(): number {
    return this.config.get<number>('TRUST_KNOWN_THRESHOLD');
  }

  get trustDecayHalfLifeMs(): number {
    return this.config.get<number>('TRUST_DECAY_HALFLIFE_MS');
  }

  get trustAnomalyWarmupN(): number {
    return this.config.get<number>('TRUST_ANOMALY_WARMUP_N');
  }

  get trustFrequencyWindowMs(): number {
    return this.config.get<number>('TRUST_FREQUENCY_WINDOW_MS');
  }

  get trustFrequencyNormalMax(): number {
    return this.config.get<number>('TRUST_FREQUENCY_NORMAL_MAX');
  }

  // --- Phase 5: Hashcash PoW (D-17) ---

  /** HMAC secret for signing PoW challenge nonces. Required, min 32 chars. Separate from JWT_SECRET (D-05). */
  get hashcashHmacSecret(): string {
    return this.config.get<string>('HASHCASH_HMAC_SECRET');
  }

  /** Challenge TTL in ms (D-03). Default 120000 (120s). */
  get hashcashChallengeTtlMs(): number {
    return this.config.get<number>('HASHCASH_CHALLENGE_TTL_MS');
  }

  /** Bounded LRU capacity for the used-nonce store (D-04). Default 10000. */
  get hashcashUsedNonceCapacity(): number {
    return this.config.get<number>('HASHCASH_USED_NONCE_CAPACITY');
  }

  /** Trust score above which PoW activates (D-08, strict >). Default 0.7. */
  get hashcashTriggerThreshold(): number {
    return this.config.get<number>('HASHCASH_TRIGGER_THRESHOLD');
  }

  /**
   * Minimum difficulty in bits (D-10, D-17). Default 18. Override to 4 in test envs for fast solving.
   * Wired into HashcashService constructor → difficultyForScore(score, min, max) on BOTH issue and verify.
   */
  get hashcashDifficultyMin(): number {
    return this.config.get<number>('HASHCASH_DIFFICULTY_MIN');
  }

  /**
   * Maximum difficulty in bits (D-10, D-17). Default 22. Override to 4 in test envs.
   * Wired into HashcashService constructor → difficultyForScore(score, min, max) on BOTH issue and verify.
   */
  get hashcashDifficultyMax(): number {
    return this.config.get<number>('HASHCASH_DIFFICULTY_MAX');
  }

  // ── Phase 6: Policy + Threat Escalation (D-23) ──

  /** Path to Casbin model.conf (FileAdapter). Default 'policy/model.conf'. */
  get policyModelPath(): string {
    return this.config.get<string>('POLICY_MODEL_PATH');
  }

  /** Path to Casbin policy.csv (FileAdapter). Default 'policy/policy.csv'. */
  get policyCsvPath(): string {
    return this.config.get<string>('POLICY_CSV_PATH');
  }

  /** Trust score above which policy returns CHALLENGE at NORMAL threat level (D-19). */
  get policyChallengeThreshold(): number {
    return this.config.get<number>('POLICY_CHALLENGE_THRESHOLD');
  }

  /** Trust score above which policy returns DENY at NORMAL threat level (D-19). */
  get policyDenyThreshold(): number {
    return this.config.get<number>('POLICY_DENY_THRESHOLD');
  }

  /** Trust score above which policy returns CHALLENGE at ELEVATED threat level (D-19). Tighter than normal. */
  get policyElevatedChallengeThreshold(): number {
    return this.config.get<number>('POLICY_ELEVATED_CHALLENGE_THRESHOLD');
  }

  /** Trust score above which policy returns DENY at ELEVATED threat level (D-19). Tighter than normal. */
  get policyElevatedDenyThreshold(): number {
    return this.config.get<number>('POLICY_ELEVATED_DENY_THRESHOLD');
  }

  /** Trust score above which policy returns CHALLENGE at CRITICAL threat level (D-19). Tighter than elevated. */
  get policyCriticalChallengeThreshold(): number {
    return this.config.get<number>('POLICY_CRITICAL_CHALLENGE_THRESHOLD');
  }

  /** Trust score above which policy returns DENY at CRITICAL threat level (D-19). Tighter than elevated. */
  get policyCriticalDenyThreshold(): number {
    return this.config.get<number>('POLICY_CRITICAL_DENY_THRESHOLD');
  }

  /** Sliding window length (ms) over which threat signals accumulate. Default 300000 (5min). */
  get threatWindowMs(): number {
    return this.config.get<number>('THREAT_WINDOW_MS');
  }

  /** Bounded array capacity per signal type (D-18). Default 10000. */
  get threatWindowMaxEvents(): number {
    return this.config.get<number>('THREAT_WINDOW_MAX_EVENTS');
  }

  /** Deny count in window that triggers ELEVATED threat level (D-20). Default 20. */
  get threatElevatedDenies(): number {
    return this.config.get<number>('THREAT_ELEVATED_DENIES');
  }

  /** Deny count in window that triggers CRITICAL threat level (D-20). Default 50. */
  get threatCriticalDenies(): number {
    return this.config.get<number>('THREAT_CRITICAL_DENIES');
  }

  /** Invalid-token count in window that triggers ELEVATED threat level (D-20). Default 30. */
  get threatElevatedInvalidTokens(): number {
    return this.config.get<number>('THREAT_ELEVATED_INVALID_TOKENS');
  }

  /** Invalid-token count in window that triggers CRITICAL threat level (D-20). Default 80. */
  get threatCriticalInvalidTokens(): number {
    return this.config.get<number>('THREAT_CRITICAL_INVALID_TOKENS');
  }

  /** Honeypot-hit count in window that triggers ELEVATED threat level (D-20). Default 5. */
  get threatElevatedHoneypot(): number {
    return this.config.get<number>('THREAT_ELEVATED_HONEYPOT');
  }

  /** Honeypot-hit count in window that triggers CRITICAL threat level (D-20). Default 15. */
  get threatCriticalHoneypot(): number {
    return this.config.get<number>('THREAT_CRITICAL_HONEYPOT');
  }

  /** MFA rate-limit hit count in window that triggers ELEVATED threat level (D-09, 14-03). Default 5. */
  get threatElevatedMfaRateLimited(): number {
    return this.config.get<number>('THREAT_ELEVATED_MFA_RATE_LIMITED');
  }

  /** MFA rate-limit hit count in window that triggers CRITICAL threat level (D-09, 14-03). Default 15. */
  get threatCriticalMfaRateLimited(): number {
    return this.config.get<number>('THREAT_CRITICAL_MFA_RATE_LIMITED');
  }

  /** Cooldown (ms) before threat level can de-escalate. Default 600000 (10min). */
  get threatCooldownMs(): number {
    return this.config.get<number>('THREAT_COOLDOWN_MS');
  }

  // --- Phase 7: MFA Challenge (D-09, D-15, D-03, D-17) ---

  /** Separate from JWT_SECRET (D-09). Joi min 32 chars. */
  get mfaJwtSecret(): string {
    return this.config.get<string>('MFA_JWT_SECRET');
  }

  /** AES-256-GCM key for TOTP secrets at rest (D-15). Base64-encoded 32-byte key. Joi min(44). */
  get mfaTotpEncryptionKey(): string {
    return this.config.get<string>('MFA_TOTP_ENCRYPTION_KEY');
  }

  /** Challenge row TTL in ms (D-03). Default 300000 (5min). Must be < mfaTokenTtlMs. */
  get mfaChallengeTtlMs(): number {
    return this.config.get<number>('MFA_CHALLENGE_TTL_MS');
  }

  /** MFA JWT TTL in ms (D-03). Default 600000 (10min). */
  get mfaTokenTtlMs(): number {
    return this.config.get<number>('MFA_TOKEN_TTL_MS');
  }

  /** Max challenges per user per mfaRateLimitWindowMs (D-17). Default 5. */
  get mfaRateLimitMax(): number {
    return this.config.get<number>('MFA_RATE_LIMIT_MAX');
  }

  /** Rate-limit window in ms (D-17). Default 60000. */
  get mfaRateLimitWindowMs(): number {
    return this.config.get<number>('MFA_RATE_LIMIT_WINDOW_MS');
  }

  // --- Phase 11: MFA Enrollment (D-11) ---

  /** TOTP issuer name shown in authenticator apps. Joi default 'ZT-Gateway'. */
  get mfaIssuerName(): string {
    return this.config.get<string>('MFA_ISSUER_NAME');
  }

  /** TTL for pending enrollment entries in ms. Joi default 600000 (10min). */
  get mfaEnrollPendingTtlMs(): number {
    return this.config.get<number>('MFA_ENROLL_PENDING_TTL_MS');
  }

  // ── Phase 8: Proxy + BOPLA (D-01, D-12) ──

  /** JSON string mapping serviceName → baseUrl. Required (D-03/D-04). Parsed by ServiceRegistryService.onModuleInit. */
  get proxyServiceRegistry(): string {
    return this.config.get<string>('PROXY_SERVICE_REGISTRY');
  }

  /** opossum volumeThreshold — min requests before tripping (default 5, D-12). */
  get proxyCbVolumeThreshold(): number {
    return this.config.get<number>('PROXY_CB_VOLUME_THRESHOLD');
  }

  /** opossum errorThresholdPercentage — % failure rate to open (default 50, D-12). */
  get proxyCbErrorThreshold(): number {
    return this.config.get<number>('PROXY_CB_ERROR_THRESHOLD');
  }

  /** opossum resetTimeout — ms OPEN before HALF-OPEN probe (default 10000, D-12). */
  get proxyCbResetTimeout(): number {
    return this.config.get<number>('PROXY_CB_RESET_TIMEOUT');
  }

  /** Max retries inside opossum action function (default 3, D-12). */
  get proxyMaxRetries(): number {
    return this.config.get<number>('PROXY_MAX_RETRIES');
  }

  /** Path to BOPLA field policy JSON (default 'policy/field-policy.json', D-05). */
  get boplaPolicyPath(): string {
    return this.config.get<string>('BOPLA_POLICY_PATH');
  }

  // ── Phase 9: Audit WAL (D-06) ──

  /** Base delay in ms for WAL exponential backoff. Default 50. */
  get auditWalBaseDelayMs(): number {
    return this.config.get<number>('AUDIT_WAL_BASE_DELAY_MS');
  }

  /** Max retries for WAL before throwing AuditExhaustedException. Default 3. */
  get auditWalMaxRetries(): number {
    return this.config.get<number>('AUDIT_WAL_MAX_RETRIES');
  }
}
