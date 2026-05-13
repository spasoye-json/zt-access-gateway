import {
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { handleTerminalError } from '../handle-terminal-error';
import type { Response } from 'express';
import { AuditExhaustedException } from '../../../audit/audit-exhausted.exception';
import { AUDIT_SIGNAL } from '../../../policy/policy-events';
import type { StageContext } from '../stage-context';
import type { TypedEvents } from '../../../shared/typed-events';
import type { MetricsService } from '../../../metrics/metrics.service';

function makeRes(): { res: Response; status: jest.Mock; json: jest.Mock; set: jest.Mock } {
  const json = jest.fn();
  const set = jest.fn();
  const status = jest.fn().mockImplementation(() => ({ json, set }));
  set.mockImplementation(() => ({ status, json }));
  const res = { status, json, set } as unknown as Response;
  return { res, status, json, set };
}

function makeCtx(): StageContext {
  return {
    req: {
      method: 'POST',
      headers: { 'x-forwarded-for': '10.1.2.3' },
      ip: '10.1.2.3',
      socket: { remoteAddress: '10.1.2.3' },
    } as unknown as StageContext['req'],
    res: {} as unknown as StageContext['res'],
    next: jest.fn() as unknown as StageContext['next'],
    requestId: 'req-abc',
    startedAt: Date.now(),
    reqPath: '/users/u1',
    ja4h: 'ja4h-fp',
    claims: { userId: 'u1' } as StageContext['claims'],
  };
}

describe('handleTerminalError', () => {
  let events: { emit: jest.Mock };
  let metrics: {
    incrementAuditFailure: jest.Mock;
    incrementRequest: jest.Mock;
  };

  beforeEach(() => {
    events = { emit: jest.fn() };
    metrics = {
      incrementAuditFailure: jest.fn(),
      incrementRequest: jest.fn(),
    };
  });

  it('AuditExhaustedException → 503 + Retry-After:5 + audit_unavailable; emits AUDIT_SIGNAL; increments audit failure', () => {
    const { res, status, json, set } = makeRes();
    const ctx = makeCtx();
    handleTerminalError(
      res,
      new AuditExhaustedException('wal full'),
      ctx,
      events as unknown as TypedEvents,
      metrics as unknown as MetricsService,
    );
    expect(metrics.incrementAuditFailure).toHaveBeenCalledTimes(1);
    expect(events.emit).toHaveBeenCalledWith(
      AUDIT_SIGNAL,
      expect.objectContaining({
        type: AUDIT_SIGNAL,
        userId: 'u1',
        ja4h: 'ja4h-fp',
        resource: '/users/u1',
        action: 'POST',
        requestId: 'req-abc',
      }),
    );
    expect(status).toHaveBeenCalledWith(503);
    expect(set).toHaveBeenCalledWith('Retry-After', '5');
    expect(json).toHaveBeenCalledWith({
      error: 'audit_unavailable',
      requestId: 'req-abc',
    });
  });

  it('ServiceUnavailableException → 502 proxy_unavailable', () => {
    const { res, status, json } = makeRes();
    handleTerminalError(
      res,
      new ServiceUnavailableException('upstream'),
      makeCtx(),
      events as unknown as TypedEvents,
      metrics as unknown as MetricsService,
    );
    expect(status).toHaveBeenCalledWith(502);
    expect(json).toHaveBeenCalledWith({
      error: 'proxy_unavailable',
      requestId: 'req-abc',
    });
  });

  it('UnauthorizedException → 401 auth_invalid with message', () => {
    const { res, status, json } = makeRes();
    handleTerminalError(
      res,
      new UnauthorizedException('bad token'),
      makeCtx(),
      events as unknown as TypedEvents,
      metrics as unknown as MetricsService,
    );
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'auth_invalid', requestId: 'req-abc' }),
    );
  });

  it('any other error → re-throws', () => {
    const { res } = makeRes();
    const boom = new Error('boom');
    expect(() =>
      handleTerminalError(
        res,
        boom,
        makeCtx(),
        events as unknown as TypedEvents,
        metrics as unknown as MetricsService,
      ),
    ).toThrow(boom);
  });
});
