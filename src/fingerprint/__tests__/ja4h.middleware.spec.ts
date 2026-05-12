import { EventEmitter2 } from '@nestjs/event-emitter';
import { FingerprintStore } from '../fingerprint.store';
import { Ja4hMiddleware } from '../ja4h.middleware';
import { computeJa4h } from '../ja4h.util';
import * as sleepUtil from '../../shared/sleep.util';

// Mock sleep utility so tarpit tests are instant
jest.mock('../../shared/sleep.util', () => ({
  sleep: jest.fn().mockResolvedValue(undefined),
  randomDelay: jest.fn().mockReturnValue(3000),
}));

function mockReq(overrides: Partial<any> = {}): any {
  return {
    rawHeaders: ['Host', 'example.com', 'Accept', 'text/html'],
    headers: { host: 'example.com', accept: 'text/html' },
    method: 'GET',
    httpVersion: '1.1',
    ...overrides,
  };
}

function mockRes(): any {
  const json = jest.fn();
  const status = jest.fn().mockReturnValue({ json });
  return { status, json, _json: json };
}

describe('Ja4hMiddleware', () => {
  let store: FingerprintStore;
  let middleware: Ja4hMiddleware;
  let next: jest.Mock;

  beforeEach(() => {
    store = new FingerprintStore(new EventEmitter2());
    middleware = new Ja4hMiddleware(store);
    next = jest.fn();
    (sleepUtil.sleep as jest.Mock).mockClear();
    (sleepUtil.randomDelay as jest.Mock).mockClear();
  });

  it('attaches x-ja4h to req and calls next() for non-blacklisted fingerprint', async () => {
    const req = mockReq();
    const res = mockRes();

    await middleware.use(req, res, next);

    expect(req['x-ja4h']).toBeDefined();
    expect(typeof req['x-ja4h']).toBe('string');
    expect(req['x-ja4h'].length).toBe(64); // SHA-256 hex = 64 chars
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
  });

  it('does NOT call next() and responds with 403 for blacklisted fingerprint', async () => {
    const req = mockReq();
    const fingerprint = computeJa4h(req);
    store.add(fingerprint, { ttlMs: 60000, isTerminal: true });

    const res = mockRes();

    await middleware.use(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.status(403).json).toHaveBeenCalledWith({
      statusCode: 403,
      message: 'Forbidden',
    });
  });

  it('calls sleep with value between 2000-5000 for blacklisted fingerprint', async () => {
    const req = mockReq();
    const fingerprint = computeJa4h(req);
    store.add(fingerprint, { ttlMs: 60000, isTerminal: false });

    const res = mockRes();

    await middleware.use(req, res, next);

    expect(sleepUtil.randomDelay).toHaveBeenCalledWith(2000, 5000);
    expect(sleepUtil.sleep).toHaveBeenCalledWith(3000); // mocked randomDelay returns 3000
  });

  it('works with empty rawHeaders (produces valid hash, does not throw)', async () => {
    const req = mockReq({ rawHeaders: [], headers: {} });
    const res = mockRes();

    await expect(middleware.use(req, res, next)).resolves.not.toThrow();
    expect(next).toHaveBeenCalledTimes(1);
    expect(req['x-ja4h']).toBeDefined();
  });
});
