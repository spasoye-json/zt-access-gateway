import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { IS_PUBLIC_KEY } from '../shared/public.decorator';
import { AuthService } from './auth.service';
import { TokenRevocationService } from './token-revocation.service';
import { extractJa4h } from '../shared/request-context.util';
import {
  AUTH_INVALID_TOKEN,
  type ThreatSignalPayload,
} from '../policy/policy-events';

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
    const isPublic = this.reflector.getAllAndOverride<boolean>(
      IS_PUBLIC_KEY,
      [context.getHandler(), context.getClass()],
    );
    if (isPublic) return true;

    const request = context.switchToHttp().getRequest();
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
    request: { ip?: string; socket?: { remoteAddress?: string } },
    userId: string | undefined,
  ): void {
    const payload: ThreatSignalPayload = {
      type: AUTH_INVALID_TOKEN,
      ip: request.ip ?? request.socket?.remoteAddress ?? 'unknown',
      userId,
      ja4h: extractJa4h(request as never),
      ts: Date.now(),
    };
    this.events.emit(AUTH_INVALID_TOKEN, payload);
  }

  private extractTokenFromHeader(request: { headers?: Record<string, string> }): string {
    const authorization = request.headers?.authorization;
    if (!authorization) {
      throw new UnauthorizedException('Missing authorization header');
    }
    const [scheme, token] = authorization.split(' ');
    if (scheme !== 'Bearer' || !token) {
      throw new UnauthorizedException('Invalid authorization scheme');
    }
    return token;
  }
}
