import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { IS_PUBLIC_KEY } from '../shared/public.decorator';
import { TypedEvents } from '../shared/typed-events';
import { AUTH_INVALID_TOKEN } from '../policy/policy-events';
import { AuthService } from './auth.service';
import { GATEWAY_VALIDATED } from './gateway-validated.symbol';
import { buildAuthInvalidPayload } from './auth-invalid-payload';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly auth: AuthService,
    private readonly events: TypedEvents,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const refs = [context.getHandler(), context.getClass()];
    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, refs)) return true;
    const req = context.switchToHttp().getRequest<Request & { user?: unknown }>();
    const brand = req as unknown as Record<symbol, unknown>;
    if (brand[GATEWAY_VALIDATED] === true) return true;
    const outcome = await this.auth.authenticate(req);
    if (outcome.kind === 'ok') {
      req.user = outcome.claims;
      brand[GATEWAY_VALIDATED] = true;
      return true;
    }
    if (outcome.kind === 'revoked') throw new UnauthorizedException('Token has been revoked');
    this.events.emit(AUTH_INVALID_TOKEN, buildAuthInvalidPayload(req));
    throw new UnauthorizedException(outcome.message);
  }
}
