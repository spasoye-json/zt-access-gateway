import chalk from 'chalk';
import { Logger } from '@nestjs/common';
import { GatewayMiddleware } from '../gateway.middleware';
import { AuditExhaustedException } from '../../audit/audit-exhausted.exception';
import { AUDIT_SIGNAL } from '../../policy/policy-events';
import type { PipelineOrchestrator } from '../pipeline/orchestrator';
import type { TypedEvents } from '../../shared/typed-events';
import type { MetricsService } from '../../metrics/metrics.service';

beforeAll(() => {
  chalk.level = 1;
});

/**
 * Phase D — GatewayMiddleware unit spec rewritten around the orchestrator.
 *
 * Pre-Phase-D: makeMocks() instantiated 12 collaborator services to drive
 * a 395-LOC use() method. Post-Phase-D: the middleware delegates everything
 * to PipelineOrchestrator + writeOutcome + handleTerminalError. The unit
 * surface is exactly the 4 outcome dispatches:
 *   - bypass        → next() called
 *   - short-circuit → res.status().set?.().json()
 *   - proxied       → metrics.incrementRequest('allow') + res.status().json()
 *   - terminal error → handleTerminalError branches
 */

function makeRes(): {
  res: import('express').Response;
  status: jest.Mock;
  json: jest.Mock;
  set: jest.Mock;
} {
  const json = jest.fn();
  const set = jest.fn();
  const obj: { statusCode?: number } = {};
  const status = jest.fn().mockImplementation((code: number) => {
    obj.statusCode = code;
    return { json, set };
  });
  set.mockImplementation(() => ({ status, json }));
  Object.assign(obj, { status, json, set });
  const res = obj as unknown as import('express').Response;
  return { res, status, json, set };
}

function makeReq(
  opts: { method?: string; headers?: Record<string, string> } = {},
): import('express').Request {
  return {
    method: opts.method ?? 'GET',
    headers: opts.headers ?? {},
    originalUrl: '/users/1',
    url: '/users/1',
    path: '/users/1',
    ip: '1.2.3.4',
    socket: { remoteAddress: '1.2.3.4' },
  } as unknown as import('express').Request;
}

function build(outcome?: ReturnType<PipelineOrchestrator['run']> | Error): {
  mw: GatewayMiddleware;
  orchestrator: { run: jest.Mock };
  events: { emit: jest.Mock };
  metrics: jest.Mocked<MetricsService>;
} {
  const run = jest.fn().mockImplementation(async () => {
    if (outcome instanceof Error) throw outcome;
    return outcome ?? { kind: 'bypass' };
  });
  const orchestrator = { run };
  const events = { emit: jest.fn() };
  const metrics = {
    incrementRequest: jest.fn(),
    incrementAuditFailure: jest.fn(),
  } as unknown as jest.Mocked<MetricsService>;
  const mw = new GatewayMiddleware(
    orchestrator as unknown as PipelineOrchestrator,
    events as unknown as TypedEvents,
    metrics,
  );
  return { mw, orchestrator, events, metrics };
}

describe('GatewayMiddleware (Phase D — orchestrator-driven)', () => {
  it('OPTIONS preflight → next() without invoking orchestrator', async () => {
    const { mw, orchestrator } = build();
    const next = jest.fn();
    const { res } = makeRes();
    await mw.use(makeReq({ method: 'OPTIONS' }), res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(orchestrator.run).not.toHaveBeenCalled();
  });

  it('orchestrator returns bypass → next() called; res untouched', async () => {
    const { mw } = build({ kind: 'bypass' } as never);
    const next = jest.fn();
    const { res, status, json } = makeRes();
    await mw.use(makeReq(), res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(status).not.toHaveBeenCalled();
    expect(json).not.toHaveBeenCalled();
  });

  it('orchestrator returns short-circuit (with headers) → res.set + res.status + res.json', async () => {
    const { mw, metrics } = build({
      kind: 'short-circuit',
      status: 401,
      body: { error: 'auth_required', requestId: 'x' },
      headers: { 'WWW-Authenticate': 'Bearer' },
    } as never);
    const next = jest.fn();
    const { res, status, json, set } = makeRes();
    await mw.use(makeReq(), res, next);
    expect(set).toHaveBeenCalledWith('WWW-Authenticate', 'Bearer');
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith({ error: 'auth_required', requestId: 'x' });
    expect(metrics.incrementRequest).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it('orchestrator returns proxied → incrementRequest("allow") + status + json', async () => {
    const { mw, metrics } = build({
      kind: 'proxied',
      status: 200,
      body: { id: 'u1' },
    } as never);
    const next = jest.fn();
    const { res, status, json } = makeRes();
    await mw.use(makeReq(), res, next);
    expect(metrics.incrementRequest).toHaveBeenCalledWith('allow');
    expect(status).toHaveBeenCalledWith(200);
    expect(json).toHaveBeenCalledWith({ id: 'u1' });
  });

  it('emits an opening lifecycle frame before the orchestrator runs', async () => {
    const logs: string[] = [];
    const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation((m) => {
      logs.push(String(m));
    });
    const { mw } = build({ kind: 'bypass' } as never);
    const next = jest.fn();
    const { res } = makeRes();
    await mw.use(
      makeReq({ headers: { 'user-agent': 'curl/8.0', 'x-request-id': 'abcdef0123' } }),
      res,
      next,
    );
    const opening = logs.find((l) => l.includes('──▶'));
    expect(opening).toBeDefined();
    expect(opening).toContain('GET');
    expect(opening).toContain('/users/1');
    expect(opening).toContain('ip=1.2.3.4');
    expect(opening).toContain('ua=curl/8.0');
    expect(opening).toContain('abcdef01'); // short id (8 hex chars)
    logSpy.mockRestore();
  });

  it('emits a closing lifecycle frame after the outcome is written', async () => {
    const logs: string[] = [];
    const logSpy = jest.spyOn(Logger.prototype, 'log').mockImplementation((m) => {
      logs.push(String(m));
    });
    const { mw } = build({ kind: 'proxied', status: 200, body: {} } as never);
    const next = jest.fn();
    const { res } = makeRes();
    await mw.use(makeReq({ headers: { 'x-request-id': 'abcdef0123' } }), res, next);
    const closing = logs.find((l) => l.includes('◀──'));
    expect(closing).toBeDefined();
    expect(closing).toContain('200');
    expect(closing).toMatch(/total=\d+ms/);
    expect(closing).toContain('abcdef01');
    logSpy.mockRestore();
  });

  it('orchestrator throws AuditExhaustedException → 503 + Retry-After + AUDIT_SIGNAL emitted', async () => {
    const { mw, events, metrics } = build(new AuditExhaustedException('wal full'));
    const next = jest.fn();
    const { res, status, json, set } = makeRes();
    await mw.use(makeReq(), res, next);
    expect(metrics.incrementAuditFailure).toHaveBeenCalledTimes(1);
    expect(events.emit).toHaveBeenCalledWith(
      AUDIT_SIGNAL,
      expect.objectContaining({ type: AUDIT_SIGNAL }),
    );
    expect(status).toHaveBeenCalledWith(503);
    expect(set).toHaveBeenCalledWith('Retry-After', '5');
    expect(json).toHaveBeenCalledWith(expect.objectContaining({ error: 'audit_unavailable' }));
  });
});
