import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createRemoteJWKSet, errors, jwtVerify } from 'jose';
import type { JWTVerifyOptions } from 'jose';

export interface UserClaims {
  userId: string;
  roles: string[];
  sessionId: string;
  deviceId?: string;
  ip?: string;
  issuer?: string;
  audience?: string | string[];
  issuedAt?: number;
  expiresAt?: number;
  [key: string]: any;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private remoteJwks?: ReturnType<typeof createRemoteJWKSet>;

  constructor(private configService: ConfigService) {}

  async validateAuthorizationHeader(authorizationHeader: unknown): Promise<UserClaims> {
    const token = this.extractBearerToken(authorizationHeader);
    const claims = await this.validateToken(token);
    if (!claims) {
      throw new UnauthorizedException('Invalid token');
    }
    return claims;
  }

  extractBearerToken(authorizationHeader: unknown): string {
    if (!authorizationHeader || typeof authorizationHeader !== 'string') {
      throw new UnauthorizedException('Authorization header is required');
    }

    const tokenMatch = authorizationHeader.match(/^Bearer\s+(.+)$/i);
    if (!tokenMatch) {
      throw new UnauthorizedException('Invalid token format. Use Bearer token.');
    }

    const token = tokenMatch[1];
    if (token.length < 10 || token.length > 10000) {
      throw new UnauthorizedException('Invalid token length');
    }

    return token;
  }

  async validateToken(token: string): Promise<UserClaims | null> {
    if (!token || typeof token !== 'string') {
      this.logger.warn('Invalid token provided for validation');
      throw new UnauthorizedException('Invalid token format');
    }

    if (token.length < 10 || token.length > 10000) {
      this.logger.warn('Token length not within expected range');
      throw new UnauthorizedException('Invalid token length');
    }

    try {
      const algorithm = (this.configService.get<string>('JWT_ALGORITHM') || 'HS256')
        .toUpperCase()
        .trim();

      const issuer = this.configService.get<string>('JWT_ISSUER') || undefined;
      const audience = this.configService.get<string>('JWT_AUDIENCE') || undefined;
      const clockTolerance = Number(this.configService.get('JWT_CLOCK_TOLERANCE') ?? 5);

      const verifyOptions: JWTVerifyOptions = {
        algorithms: [algorithm],
        issuer,
        audience,
        clockTolerance,
      };

      let payload: any;

      if (algorithm.startsWith('HS')) {
        const secret = this.configService.get<string>('JWT_SECRET');
        if (!secret) {
          this.logger.error('JWT secret not configured');
          throw new Error('JWT secret not configured');
        }

        const secretKey = new TextEncoder().encode(secret);
        const result = await jwtVerify(token, secretKey, verifyOptions);
        payload = result.payload;
      } else if (algorithm.startsWith('RS') || algorithm.startsWith('ES')) {
        const jwksUri = this.configService.get<string>('JWT_JWKS_URI');
        if (!jwksUri) {
          this.logger.error('JWT_JWKS_URI not configured for asymmetric JWT validation');
          throw new Error('JWT_JWKS_URI not configured');
        }

        if (!this.remoteJwks) {
          this.remoteJwks = createRemoteJWKSet(new URL(jwksUri));
        }

        const result = await jwtVerify(token, this.remoteJwks, verifyOptions);
        payload = result.payload;
      } else {
        throw new Error(`Unsupported JWT algorithm: ${algorithm}`);
      }

      if (!payload || typeof payload !== 'object') {
        this.logger.warn('Invalid token payload');
        throw new UnauthorizedException('Invalid token payload');
      }

      const userId =
        (typeof (payload as any).userId === 'string' && (payload as any).userId) ||
        (typeof payload.sub === 'string' && payload.sub);

      if (!userId) {
        this.logger.warn('Token missing required user identifier claim');
        throw new UnauthorizedException('Invalid token: missing user ID');
      }

      const roles = this.extractRoles(payload);
      const sessionId =
        (typeof (payload as any).sessionId === 'string' && (payload as any).sessionId) ||
        (typeof (payload as any).sid === 'string' && (payload as any).sid) ||
        (typeof payload.jti === 'string' && payload.jti) ||
        '';

      const issuerClaim = typeof (payload as any).iss === 'string' ? (payload as any).iss : undefined;
      const audienceClaim =
        typeof (payload as any).aud === 'string' || Array.isArray((payload as any).aud)
          ? (payload as any).aud
          : undefined;
      const issuedAtClaim = typeof payload.iat === 'number' ? payload.iat : undefined;
      const expiresAtClaim = typeof payload.exp === 'number' ? payload.exp : undefined;

      return {
        ...(payload as Record<string, any>),
        userId,
        roles,
        sessionId,
        issuer: issuerClaim,
        audience: audienceClaim,
        issuedAt: issuedAtClaim,
        expiresAt: expiresAtClaim,
      } satisfies UserClaims;
    } catch (error) {
      const err = error as any;
      this.logger.warn(`Token validation failed: ${err?.message || err}`);

      if (err instanceof UnauthorizedException) {
        throw err;
      }

      if (err instanceof errors.JWTExpired) {
        throw new UnauthorizedException('Token has expired');
      }
      if (err instanceof errors.JWTInvalid) {
        throw new UnauthorizedException('Invalid token');
      }
      if (err instanceof errors.JWTClaimValidationFailed) {
        throw new UnauthorizedException('Token claim validation failed');
      }

      throw new UnauthorizedException('Token validation failed');
    }
  }

  private extractRoles(payload: any): string[] {
    const roles: string[] = [];

    if (Array.isArray(payload?.roles)) {
      roles.push(...payload.roles.filter((r: any) => typeof r === 'string'));
    } else if (typeof payload?.roles === 'string') {
      roles.push(
        ...payload.roles
          .split(',')
          .map((r: string) => r.trim())
          .filter(Boolean),
      );
    }

    const realmRoles = payload?.realm_access?.roles;
    if (Array.isArray(realmRoles)) {
      roles.push(...realmRoles.filter((r: any) => typeof r === 'string'));
    }

    const resourceAccess = payload?.resource_access;
    if (resourceAccess && typeof resourceAccess === 'object') {
      for (const client of Object.values(resourceAccess)) {
        const clientRoles = (client as any)?.roles;
        if (Array.isArray(clientRoles)) {
          roles.push(...clientRoles.filter((r: any) => typeof r === 'string'));
        }
      }
    }

    return [...new Set(roles)];
  }
}
