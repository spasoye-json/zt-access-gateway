import { writeOutcome } from '../write-outcome';
import type { Response, NextFunction } from 'express';
import type { MetricsService } from '../../../metrics/metrics.service';

function makeRes(): { res: Response; status: jest.Mock; json: jest.Mock; set: jest.Mock } {
  const json = jest.fn();
  const status = jest.fn().mockImplementation(() => ({ json, set }));
  const set = jest.fn().mockImplementation(() => ({ status, json }));
  // simulate chained res.set(...).status(...).json(...) and res.status(...).json(...)
  const res = { status, json, set } as unknown as Response;
  return { res, status, json, set };
}

const metrics = { incrementRequest: jest.fn() } as unknown as MetricsService & {
  incrementRequest: jest.Mock;
};

describe('writeOutcome', () => {
  beforeEach(() => jest.clearAllMocks());

  it('bypass → calls next() and does not touch res', () => {
    const { res, status, json } = makeRes();
    const next = jest.fn() as unknown as NextFunction;
    writeOutcome(res, next, { kind: 'bypass' }, metrics);
    expect(next).toHaveBeenCalledTimes(1);
    expect(status).not.toHaveBeenCalled();
    expect(json).not.toHaveBeenCalled();
  });

  it('short-circuit → writes status + body; no metric increment', () => {
    const { res, status, json, set } = makeRes();
    const next = jest.fn() as unknown as NextFunction;
    writeOutcome(
      res,
      next,
      { kind: 'short-circuit', status: 401, body: { error: 'auth_required' } },
      metrics,
    );
    expect(next).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith({ error: 'auth_required' });
    expect(set).not.toHaveBeenCalled();
    expect((metrics.incrementRequest as jest.Mock)).not.toHaveBeenCalled();
  });

  it('short-circuit with headers → applies each header before status/json', () => {
    const { res, status, json, set } = makeRes();
    const next = jest.fn() as unknown as NextFunction;
    writeOutcome(
      res,
      next,
      {
        kind: 'short-circuit',
        status: 429,
        body: { error: 'proof_of_work_required' },
        headers: { 'X-Hashcash-Challenge': 'abc:5', 'Retry-After': '1' },
      },
      metrics,
    );
    expect(set).toHaveBeenCalledWith('X-Hashcash-Challenge', 'abc:5');
    expect(set).toHaveBeenCalledWith('Retry-After', '1');
    expect(status).toHaveBeenCalledWith(429);
    expect(json).toHaveBeenCalledWith({ error: 'proof_of_work_required' });
  });

  it('proxied → increments allow + writes status + body', () => {
    const { res, status, json } = makeRes();
    const next = jest.fn() as unknown as NextFunction;
    writeOutcome(
      res,
      next,
      { kind: 'proxied', status: 200, body: { id: 'u1' } },
      metrics,
    );
    expect((metrics.incrementRequest as jest.Mock)).toHaveBeenCalledWith('allow');
    expect(status).toHaveBeenCalledWith(200);
    expect(json).toHaveBeenCalledWith({ id: 'u1' });
  });

  it('continue → throws (programmer error: pipeline did not terminate)', () => {
    const { res } = makeRes();
    const next = jest.fn() as unknown as NextFunction;
    expect(() =>
      writeOutcome(res, next, { kind: 'continue' }, metrics),
    ).toThrow(/did not terminate/);
  });
});
