import type { ExecutionContext } from '@nestjs/common';
import { GatewayOnlyGuard } from '../../../microservices/gateway-only.guard';

const makeContext = (req: any): ExecutionContext =>
  ({
    switchToHttp: () => ({
      getRequest: () => req,
    }),
  } as ExecutionContext);

describe('GatewayOnlyGuard', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it('rejects non-TLS requests when insecure HTTP is not allowed', () => {
    const guard = new GatewayOnlyGuard();
    const req = {
      headers: { 'x-gateway-request': 'true' },
      socket: { encrypted: false },
    };

    expect(guard.canActivate(makeContext(req))).toBe(false);
  });

  it('accepts non-TLS requests when insecure HTTP is allowed and header is present', () => {
    process.env.ALLOW_INSECURE_MICROSERVICE_HTTP = 'true';
    const guard = new GatewayOnlyGuard();
    const req = {
      headers: { 'x-gateway-request': 'true' },
      socket: { encrypted: false },
    };

    expect(guard.canActivate(makeContext(req))).toBe(true);
  });

  it('rejects TLS requests without authorization', () => {
    const guard = new GatewayOnlyGuard();
    const req = {
      socket: { encrypted: true, authorized: false },
    };

    expect(guard.canActivate(makeContext(req))).toBe(false);
  });

  it('accepts TLS requests with authorized gateway certificate', () => {
    process.env.GATEWAY_CLIENT_CERT_CNS = 'gateway,other';
    const guard = new GatewayOnlyGuard();
    const req = {
      socket: {
        encrypted: true,
        authorized: true,
        getPeerCertificate: () => ({ subject: { CN: 'gateway' } }),
      },
    };

    expect(guard.canActivate(makeContext(req))).toBe(true);
  });

  it('rejects TLS requests with non-allowed certificate subject', () => {
    process.env.GATEWAY_CLIENT_CERT_CNS = 'gateway';
    const guard = new GatewayOnlyGuard();
    const req = {
      socket: {
        encrypted: true,
        authorized: true,
        getPeerCertificate: () => ({ subject: { CN: 'not-gateway' } }),
      },
    };

    expect(guard.canActivate(makeContext(req))).toBe(false);
  });
});
