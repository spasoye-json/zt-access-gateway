import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";
import type { Request } from 'express';

const parseAllowedSubjects = (value?: string): string[] => {
  if (!value) {
    return [];
  }

  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
};

@Injectable()
export class GatewayOnlyGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();
    const allowInsecure = process.env.ALLOW_INSECURE_MICROSERVICE_HTTP === 'true';

    const isTls = Boolean((req.socket as any)?.encrypted);
    if (!isTls) {
      if (!allowInsecure) {
        return false;
      }
      return req.headers['x-gateway-request'] === 'true';
    }

    const authorized = Boolean((req.socket as any)?.authorized || (req as any)?.client?.authorized);
    if (!authorized) {
      return false;
    }

    const allowedSubjects = parseAllowedSubjects(
      process.env.GATEWAY_CLIENT_CERT_CNS || process.env.GATEWAY_CLIENT_CERT_CN || 'gateway',
    );
    if (allowedSubjects.length == 0) {
      return true;
    }

    const cert = (req.socket as any)?.getPeerCertificate?.();
    const commonName = cert?.subject?.CN;
    if (!commonName) {
      return false;
    }

    return allowedSubjects.includes(commonName);
  }
}
