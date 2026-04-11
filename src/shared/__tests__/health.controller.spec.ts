import { HealthController } from '../health.controller';

describe('HealthController', () => {
  let controller: HealthController;

  beforeEach(() => {
    controller = new HealthController();
  });

  it('GET /health returns status ok', () => {
    const result = controller.check();
    expect(result).toMatchObject({ status: 'ok' });
  });

  it('response contains ISO timestamp', () => {
    const result = controller.check();
    expect(result.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  });
});
