import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../shared/public.decorator';
import { AuthService } from './auth.service';
import { TokenRevocationService } from './token-revocation.service';

/**
 * Global JWT authentication guard (APP_GUARD).
 * AUTH-07: @Public() routes bypass validation.
 * AUTH-06: Extracts Bearer token, validates via AuthService, attaches UserClaims to request.user.
 * TREV-04 / D-08: Revocation check AFTER jwtVerify, BEFORE downstream processing.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly authService: AuthService,
    private readonly revocationService: TokenRevocationService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // AUTH-07: @Public() bypass
    const isPublic = this.reflector.getAllAndOverride<boolean>(
      IS_PUBLIC_KEY,
      [context.getHandler(), context.getClass()],
    );
    if (isPublic) return true;

    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    // AUTH-06: validate and extract claims
    const claims = await this.authService.validateToken(token);

    // TREV-04 / D-08: revocation check AFTER jwtVerify, BEFORE downstream
    if (this.revocationService.isRevoked(claims.jti)) {
      throw new UnauthorizedException('Token has been revoked');
    }

    // D-02: attach to request.user
    request.user = claims;
    return true;
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
