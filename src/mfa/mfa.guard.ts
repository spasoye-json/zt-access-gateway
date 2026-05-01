import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { IS_PUBLIC_KEY } from '../shared/public.decorator';
import { extractIp, extractDeviceId, extractJa4h } from '../shared/request-context.util';
import type { UserClaims } from '../auth/interfaces/user-claims.interface';
import { MfaService } from './mfa.service';

/**
 * Phase 7 — MfaGuard validates X-MFA-Token header (D-02).
 *
 * Reads X-MFA-Token from request headers, calls MfaService.validateMfaToken.
 * On success: attaches result.claims to request.mfaToken for downstream consumers.
 * On failure: throws UnauthorizedException({ error: 'mfa_invalid', reason }).
 *
 * D-20: Guard is NOT registered as APP_GUARD in Phase 7.
 * Phase 10 GatewayMiddleware will register it in the pipeline.
 */
@Injectable()
export class MfaGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly mfa: MfaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();

    // OPTIONS passthrough
    if (request.method === 'OPTIONS') return true;

    // @Public() bypass
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const mfaToken = request.headers['x-mfa-token'] as string | undefined;
    if (!mfaToken) {
      throw new UnauthorizedException({ error: 'mfa_required' });
    }

    const user = (request as Request & { user?: UserClaims }).user;
    if (!user || !user.userId || !user.deviceId) {
      throw new UnauthorizedException({ error: 'mfa_required' });
    }

    const ip = extractIp(request);
    const deviceId = extractDeviceId(request);
    const ja4h = extractJa4h(request as never);

    const result = await this.mfa.validateMfaToken(
      mfaToken,
      user.userId,
      deviceId ?? '',
      ip,
      ja4h,
    );

    if (!result.ok) {
      throw new UnauthorizedException({ error: 'mfa_invalid', reason: (result as { ok: false; reason: string }).reason });
    }

    // Attach validated claims to request for Phase 10 consumers
    (request as Request & { mfaToken?: unknown }).mfaToken = result.claims;
    return true;
  }
}
