import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { IS_PUBLIC_KEY } from '../shared/public.decorator';
import { AuthService } from './auth.service';
import { TokenRevocationService } from './token-revocation.service';
import { extractIp, extractJa4h } from '../shared/request-context.util';
import { AUTH_INVALID_TOKEN, type ThreatSignalPayload } from '../policy/policy-events';
import type { UserClaims, AuthenticatedClaims } from './interfaces/user-claims.interface';

interface AuthRequest {
  ip?: string;
  headers?: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
  user?: UserClaims | AuthenticatedClaims;
}

/**
 * Global JWT authentication guard (APP_GUARD).
 * AUTH-07: @Public() routes bypass validation.
 * AUTH-06: Extracts Bearer token, validates via AuthService, attaches UserClaims to request.user.
 * TREV-04 / D-08: Revocation check AFTER jwtVerify, BEFORE downstream processing.
 *
 * Phase 6 (D-14): emits AUTH_INVALID_TOKEN to the threat-signal bus on every
 * UnauthorizedException exit (missing header, bad scheme, validateToken throw,
 * revocation hit). Emit happens at the guard catch site (request-aware) — not
 * inside AuthService — to keep AuthService request-agnostic.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly authService: AuthService,
    private readonly revocationService: TokenRevocationService,
    private readonly events: EventEmitter2,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // AUTH-07: @Public() bypass
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const request = context.switchToHttp().getRequest<AuthRequest>();

    // Phase A2 — branded-claims short-circuit (was Phase 13 D-04/D-05 Symbol sentinel).
    // GatewayMiddleware sets req.user = AuthenticatedClaims AFTER step 5 (validateToken)
    // and step 6 (isRevoked) succeed. The brand field is unknown to every DTO, so the
    // global ValidationPipe (whitelist + forbidNonWhitelisted) strips it from bodies;
    // it cannot be supplied by an attacker. Standalone routes (no GatewayMiddleware)
    // leave req.user undefined and fall through to full validation (D-07).
    if (request.user && '__authenticatedByGateway' in request.user) {
      return true;
    }

    let userId: string | undefined;
    try {
      const token = this.extractTokenFromHeader(request);

      // AUTH-06: validate and extract claims
      const claims = await this.authService.validateToken(token);
      userId = claims.userId;

      // TREV-04 / D-08: revocation check AFTER jwtVerify, BEFORE downstream
      if (this.revocationService.isRevoked(claims.jti)) {
        throw new UnauthorizedException('Token has been revoked');
      }

      // D-02: attach to request.user
      request.user = claims;
      return true;
    } catch (err) {
      // D-14: emit auth.invalid_token only on UnauthorizedException paths.
      // Other errors (DB failures, programmer bugs) are NOT auth signals.
      if (err instanceof UnauthorizedException) {
        this.emitInvalid(request, userId);
      }
      throw err;
    }
  }

  private emitInvalid(
    request: {
      ip?: string;
      headers?: Record<string, string | string[] | undefined>;
      socket?: { remoteAddress?: string };
    },
    userId: string | undefined,
  ): void {
    // WR-04: route IP extraction through the canonical extractIp helper so
    // trusted-proxy X-Forwarded-For handling matches the rest of the pipeline
    // (gateway.middleware.ts uses extractIp for all telemetry).
    const payload: ThreatSignalPayload = {
      type: AUTH_INVALID_TOKEN,
      ip: extractIp(request as never),
      userId,
      ja4h: extractJa4h(request as never),
      ts: Date.now(),
    };
    this.events.emit(AUTH_INVALID_TOKEN, payload);
  }

  private extractTokenFromHeader(request: {
    headers?: Record<string, string | string[] | undefined>;
  }): string {
    // WR-02: Express IncomingHttpHeaders typings allow string | string[] |
    // undefined. A client sending duplicate Authorization headers produces an
    // array, and calling .split on an array throws TypeError — bypassing
    // the D-14 UnauthorizedException emission path. Normalize first.
    const raw = request.headers?.authorization;
    const authorization = Array.isArray(raw) ? raw[0] : raw;
    if (!authorization || typeof authorization !== 'string') {
      throw new UnauthorizedException('Missing authorization header');
    }
    const [scheme, token] = authorization.split(' ');
    if (scheme !== 'Bearer' || !token) {
      throw new UnauthorizedException('Invalid authorization scheme');
    }
    return token;
  }
}
