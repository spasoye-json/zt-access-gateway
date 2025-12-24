import { ConfigService } from '@nestjs/config';
import { ServiceRegistryService } from '../../../src/proxy/service-registry.service';

const makeConfig = (registry?: string) =>
  ({ get: (key: string) => (key === 'SERVICE_REGISTRY' ? registry : undefined) } as ConfigService);

describe('ServiceRegistryService', () => {
  it('allows only configured hosts', () => {
    const registry = new ServiceRegistryService(
      makeConfig('{"users-service":"https://users.internal:3001"}'),
    );

    expect(registry.isAllowedTarget(new URL('https://users.internal:3001/users'))).toBe(true);
    expect(registry.isAllowedTarget(new URL('https://evil.internal:3001/users'))).toBe(false);
  });

  it('falls back to defaults when registry is empty', () => {
    const registry = new ServiceRegistryService(makeConfig(undefined));
    expect(registry.isAllowedTarget(new URL('https://users-service:3001/users'))).toBe(true);
  });
});
