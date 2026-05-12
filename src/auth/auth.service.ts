import { Injectable, UnauthorizedException } from '@nestjs/common';
import { jwtVerify, decodeProtectedHeader, importSPKI, createRemoteJWKSet, errors } from 'jose';
import type { JWTVerifyResult, KeyLike, JWTPayload } from 'jose';
import { AppConfigService } from '../config/config.service';
import { UserClaims } from './interfaces/user-claims.interface';

/**
 * JWT validation with algorithm-routed key resolution (D-03).
 * HS256 -> symmetric secret, RS256/ES256 -> SPKI public key or JWKS endpoint.
 * Rejects "none" alg explicitly (T-3-01). Maps jose errors to UnauthorizedException (T-3-07).
 */
@Injectable()
export class AuthService {
  /** Singleton JWKS function -- cached per Pitfall 2 */
  private jwksFunction: ReturnType<typeof createRemoteJWKSet> | null = null;

  constructor(private readonly config: AppConfigService) {}

  /**
   * Validate a JWT and extract UserClaims.
   * @param token Raw JWT string (without "Bearer " prefix)
   * @returns UserClaims on success
   * @throws UnauthorizedException on any validation failure
   */
  async validateToken(token: string): Promise<UserClaims> {
    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
      header = decodeProtectedHeader(token);
    } catch (error) {
      // Malformed token (not a JWT) — map to UnauthorizedException so callers
      // can return 401 instead of leaking a 500 with a JOSE error message.
      this.mapJoseError(error); // never-returns — TS narrows below
    }

    const options = {
      algorithms: ['HS256', 'RS256', 'ES256'],
      requiredClaims: ['jti', 'sub'],
      ...(this.config.jwtIssuer && { issuer: this.config.jwtIssuer }),
      ...(this.config.jwtAudience && { audience: this.config.jwtAudience }),
    };

    let result: JWTVerifyResult;
    try {
      if (header.alg === 'HS256') {
        // D-03: HS256 uses only symmetric secret -- prevents algorithm substitution
        const secret = new TextEncoder().encode(this.config.jwtSecret);
        result = await jwtVerify(token, secret, options);
      } else if (header.alg === 'RS256' || header.alg === 'ES256') {
        result = await this.verifyAsymmetric(token, header.alg, options);
      } else {
        // Rejects "none" and any other unsupported algorithm (T-3-01)
        throw new UnauthorizedException('Algorithm not allowed');
      }
    } catch (error) {
      this.mapJoseError(error);
    }

    // T-07-fix3: MFA JWTs (typ:'mfa') must only pass MfaService.validateMfaToken — reject from JwtAuthGuard (D-10).
    if ((result.payload as Record<string, unknown>).typ === 'mfa') {
      throw new UnauthorizedException('MFA token cannot be used as access token');
    }

    return this.extractClaims(result.payload);
  }

  /**
   * Verify token with asymmetric key: JWT_PUBLIC_KEY (SPKI PEM) or JWKS endpoint.
   * Separated to satisfy jwtVerify overload resolution (key vs getKey).
   * D-04: JWKS singleton cached at instance level.
   */
  private async verifyAsymmetric(
    token: string,
    alg: string,
    options: Parameters<typeof jwtVerify>[2],
  ): Promise<JWTVerifyResult> {
    const publicKeyPem = this.config.jwtPublicKey;
    if (publicKeyPem) {
      const key = await importSPKI(publicKeyPem, alg);
      return jwtVerify(token, key, options);
    }

    const jwksUri = this.config.jwksUri;
    if (jwksUri) {
      if (!this.jwksFunction) {
        this.jwksFunction = createRemoteJWKSet(new URL(jwksUri));
      }
      return jwtVerify(token, this.jwksFunction, options);
    }

    throw new UnauthorizedException('No key material for asymmetric algorithm');
  }

  /** Extract UserClaims from validated JWT payload (D-10, JA4H-04, D-11). */
  private extractClaims(payload: JWTPayload): UserClaims {
    const deviceId = payload.deviceId;
    if (typeof deviceId !== 'string' || deviceId.trim() === '') {
      throw new UnauthorizedException('Token missing deviceId claim');
    }
    // WR-04 (phase 14): never trust the shape of the roles claim. A token with
    // roles:"admin" (string) or roles:42 (number) is malformed; downstream
    // consumers (RolesGuard, AuthController.revoke) assume an array of strings
    // and either silently misbehave (substring match on a string primitive) or
    // throw (.includes on a number). Filter to a string[] defensively.
    const rawRoles: unknown = payload.roles;
    const roles = Array.isArray(rawRoles)
      ? rawRoles.filter((r): r is string => typeof r === 'string')
      : [];
    return {
      userId: payload.sub,
      roles,
      jti: payload.jti,
      exp: payload.exp,
      email: payload.email as string | undefined,
      sessionId: payload.sessionId as string | undefined,
      deviceId,
    };
  }

  /**
   * Map jose error classes to specific UnauthorizedException messages (T-3-07).
   * No internal error details leaked -- only expected error classes get specific messages.
   */
  private mapJoseError(error: unknown): never {
    if (error instanceof errors.JWTExpired) {
      throw new UnauthorizedException('Token has expired');
    }
    if (error instanceof errors.JWSSignatureVerificationFailed) {
      throw new UnauthorizedException('Invalid token signature');
    }
    if (error instanceof errors.JOSEAlgNotAllowed) {
      throw new UnauthorizedException('Algorithm not allowed');
    }
    if (error instanceof errors.JWTClaimValidationFailed) {
      throw new UnauthorizedException(`Invalid claim: ${error.claim}`);
    }
    if (error instanceof errors.JWKSNoMatchingKey) {
      throw new UnauthorizedException('No matching key found in JWKS');
    }
    if (error instanceof errors.JWKSTimeout) {
      throw new UnauthorizedException('JWKS endpoint timeout');
    }
    // Re-throw UnauthorizedException from our own code (e.g., "Algorithm not allowed")
    if (error instanceof UnauthorizedException) {
      throw error;
    }
    throw new UnauthorizedException('Invalid token');
  }
}
