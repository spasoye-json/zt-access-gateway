import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";

@Injectable()
export class GatewayOnlyGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest();

    return req.headers['x-gateway-request'] === 'true';
  }
}
