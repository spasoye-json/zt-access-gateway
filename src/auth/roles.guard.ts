import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from './roles.decorator';
import type { UserClaims } from './interfaces/user-claims.interface';

/**
 * Global RBAC guard (APP_GUARD, runs after JwtAuthGuard).
 * AUTH-08: Enforces @Roles() decorator. No @Roles() = no restriction.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles || requiredRoles.length === 0) return true;

    const { user } = context.switchToHttp().getRequest<{ user?: UserClaims }>();
    if (!user) return false;

    return requiredRoles.some((role) => user.roles?.includes(role));
  }
}
