/**
 * Phase B2 — DbService unit spec.
 *
 * Mocks the `pg` module's `Pool` constructor so we can assert query delegation,
 * transaction lifecycle (BEGIN/COMMIT/ROLLBACK + release), and onModuleDestroy
 * semantics without hitting Postgres.
 */

const poolInstances: MockPool[] = [];

interface MockPoolClient {
  query: jest.Mock;
  release: jest.Mock;
}

interface MockPool {
  query: jest.Mock;
  connect: jest.Mock;
  end: jest.Mock;
  __client: MockPoolClient;
}

function makeClient(): MockPoolClient {
  return {
    query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
    release: jest.fn(),
  };
}

function makePool(): MockPool {
  const client = makeClient();
  return {
    query: jest.fn().mockResolvedValue({ rows: [{ ok: 1 }], rowCount: 1 }),
    connect: jest.fn().mockResolvedValue(client),
    end: jest.fn().mockResolvedValue(undefined),
    __client: client,
  };
}

jest.mock('pg', () => ({
  __esModule: true,
  Pool: jest.fn().mockImplementation(() => {
    const p = makePool();
    poolInstances.push(p);
    return p;
  }),
}));

import { DbService } from '../db.service';
import type { ServerConfig } from '../../config/slices';

function cfg(overrides: Partial<ServerConfig> = {}): ServerConfig {
  return {
    databaseUrl: 'postgresql://localhost:5432/test',
    dbPoolMax: 7,
    ...overrides,
  } as unknown as ServerConfig;
}

describe('DbService', () => {
  beforeEach(() => {
    poolInstances.length = 0;
  });

  it('constructor builds a Pool with connectionString + dbPoolMax', () => {
    new DbService(cfg({ dbPoolMax: 11 }));
    const { Pool } = require('pg') as { Pool: jest.Mock };
    expect(Pool).toHaveBeenLastCalledWith({
      connectionString: 'postgresql://localhost:5432/test',
      max: 11,
    });
  });

  it('constructor falls back to max=25 when dbPoolMax is unset', () => {
    new DbService(cfg({ dbPoolMax: undefined }));
    const { Pool } = require('pg') as { Pool: jest.Mock };
    expect(Pool).toHaveBeenLastCalledWith({
      connectionString: 'postgresql://localhost:5432/test',
      max: 25,
    });
  });

  it('query() delegates to pool.query with sql + params', async () => {
    const svc = new DbService(cfg());
    const pool = poolInstances[poolInstances.length - 1];
    const result = await svc.query('SELECT $1::int AS x', [42]);
    expect(pool.query).toHaveBeenCalledWith('SELECT $1::int AS x', [42]);
    expect(result.rows[0]).toEqual({ ok: 1 });
  });

  it('tx() success: BEGIN → fn(client) → COMMIT → release; returns fn result', async () => {
    const svc = new DbService(cfg());
    const pool = poolInstances[poolInstances.length - 1];
    const out = await svc.tx(async (c) => {
      await c.query('SELECT 1');
      return 'value';
    });
    expect(out).toBe('value');
    const calls = pool.__client.query.mock.calls.map((c) => c[0]);
    expect(calls[0]).toBe('BEGIN');
    expect(calls).toContain('SELECT 1');
    expect(calls[calls.length - 1]).toBe('COMMIT');
    expect(pool.__client.release).toHaveBeenCalledTimes(1);
  });

  it('tx() error: ROLLBACK on throw, releases client, rethrows original error', async () => {
    const svc = new DbService(cfg());
    const pool = poolInstances[poolInstances.length - 1];
    const boom = new Error('inner fail');
    await expect(
      svc.tx(async () => {
        throw boom;
      }),
    ).rejects.toBe(boom);
    const calls = pool.__client.query.mock.calls.map((c) => c[0]);
    expect(calls[0]).toBe('BEGIN');
    expect(calls).toContain('ROLLBACK');
    expect(pool.__client.release).toHaveBeenCalledTimes(1);
  });

  it('tx() error: ROLLBACK failure does not mask the original error', async () => {
    const svc = new DbService(cfg());
    const pool = poolInstances[poolInstances.length - 1];
    pool.__client.query.mockImplementation((sql: string) => {
      if (sql === 'BEGIN') return Promise.resolve({ rows: [], rowCount: 0 });
      if (sql === 'ROLLBACK') return Promise.reject(new Error('rollback failed'));
      return Promise.resolve({ rows: [], rowCount: 0 });
    });
    const boom = new Error('inner fail');
    await expect(
      svc.tx(async () => {
        throw boom;
      }),
    ).rejects.toBe(boom);
  });

  it('onModuleDestroy() calls pool.end() exactly once', async () => {
    const svc = new DbService(cfg());
    const pool = poolInstances[poolInstances.length - 1];
    await svc.onModuleDestroy();
    expect(pool.end).toHaveBeenCalledTimes(1);
  });

  it('unsafePool() returns the same Pool instance built in constructor', () => {
    const svc = new DbService(cfg());
    const pool = poolInstances[poolInstances.length - 1];
    expect(svc.unsafePool()).toBe(pool);
  });
});
