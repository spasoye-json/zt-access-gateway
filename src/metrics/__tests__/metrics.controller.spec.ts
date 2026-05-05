import { Reflector } from '@nestjs/core';
import type { Response } from 'express';
import { MetricsController } from '../metrics.controller';
import type { MetricsService } from '../metrics.service';
import { IS_PUBLIC_KEY } from '../../shared/public.decorator';

function makeRes(): jest.Mocked<Response> {
  const res = {} as jest.Mocked<Response>;
  res.set = jest.fn().mockReturnValue(res);
  res.status = jest.fn().mockReturnValue(res);
  res.send = jest.fn().mockReturnValue(res);
  return res;
}

describe('MetricsController', () => {
  let svc: jest.Mocked<MetricsService>;
  let ctrl: MetricsController;

  beforeEach(() => {
    svc = { getAggregatedMetrics: jest.fn() } as unknown as jest.Mocked<MetricsService>;
    ctrl = new MetricsController(svc);
  });

  it('class has @Public() metadata so JwtAuthGuard skips it (MTRC-03)', () => {
    const reflector = new Reflector();
    const isPublic = reflector.get<boolean>(IS_PUBLIC_KEY, MetricsController);
    expect(isPublic).toBe(true);
  });

  it('returns 200 with aggregated metrics body (MTRC-03)', async () => {
    svc.getAggregatedMetrics.mockResolvedValueOnce('# HELP zt_gateway_requests_total ...\n');
    const res = makeRes();
    await ctrl.getMetrics(res);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.send).toHaveBeenCalledWith('# HELP zt_gateway_requests_total ...\n');
  });

  it('sets Content-Type: text/plain; version=0.0.4; charset=utf-8 (MTRC-03)', async () => {
    svc.getAggregatedMetrics.mockResolvedValueOnce('');
    const res = makeRes();
    await ctrl.getMetrics(res);
    expect(res.set).toHaveBeenCalledWith(
      'Content-Type',
      'text/plain; version=0.0.4; charset=utf-8',
    );
  });
});
