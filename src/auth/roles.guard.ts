import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from './roles.decorator';
import { UserClaims } from './auth.service';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles =
      this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ?? [];

    if (requiredRoles.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest<{ userClaims?: UserClaims }>();
    const roles = Array.isArray(request?.userClaims?.roles)
      ? request.userClaims.roles
      : [];

    const hasRole = roles.some((role) => requiredRoles.includes(role));
    if (!hasRole) {
      throw new ForbiddenException('Insufficient role grants');
    }

    return true;
  }
}
