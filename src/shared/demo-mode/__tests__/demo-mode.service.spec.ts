import { DemoModeService } from '../demo-mode.service';
import type { ConfigService } from '@nestjs/config';

function configWith(value: unknown): ConfigService {
  return { get: jest.fn().mockReturnValue(value) } as unknown as ConfigService;
}

describe('DemoModeService', () => {
  it('isActive() returns true when DEMO_MODE env is the string "true"', () => {
    const svc = new DemoModeService(configWith('true'));
    expect(svc.isActive()).toBe(true);
  });

  it('isActive() returns false when DEMO_MODE env is absent', () => {
    const svc = new DemoModeService(configWith(undefined));
    expect(svc.isActive()).toBe(false);
  });

  it('isActive() returns false for any non-"true" value (e.g. "false", "1", "yes")', () => {
    for (const v of ['false', '1', 'yes', '', 'TRUE']) {
      expect(new DemoModeService(configWith(v)).isActive()).toBe(false);
    }
  });
});
