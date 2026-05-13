import { Inject, Injectable, OnModuleDestroy } from '@nestjs/common';
import { Pool, type PoolClient, type QueryResult } from 'pg';
import { SERVER_CONFIG, type ServerConfig } from '../config/slices';
import type { Db } from './db.port';

/**
 * Phase B2 — shared pg.Pool owner.
 *
 * Replaces 5 separate pg.Pool({ max: 5 }) instantiations (25 connections per
 * gateway instance) with a single pool. Repositories receive this via DI under
 * the `DB` token and lose all pool-management code (no more onModuleDestroy in
 * repos). Lifecycle is owned here: NestJS calls onModuleDestroy() on shutdown.
 *
 * The migration runner in `main.ts` deliberately keeps a dedicated `pg.Client`
 * (NOT borrowed from this pool) for boot-time isolation — migrations run
 * before `app.init()` completes, so this service may not even be available
 * when migrations execute.
 */
@Injectable()
export class DbService implements Db, OnModuleDestroy {
  private readonly pool: Pool;

  constructor(@Inject(SERVER_CONFIG) cfg: ServerConfig) {
    this.pool = new Pool({
      connectionString: cfg.databaseUrl,
      max: cfg.dbPoolMax ?? 25,
    });
  }

  query<R = unknown>(
    sql: string,
    params?: ReadonlyArray<unknown>,
  ): Promise<QueryResult<R>> {
    // pg typings expect a mutable array; the readonly contract is for callers.
    return this.pool.query<R>(sql, params as unknown[] | undefined);
  }

  async tx<R>(fn: (client: PoolClient) => Promise<R>): Promise<R> {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw err;
    } finally {
      client.release();
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.pool.end();
  }

  /**
   * Test-infrastructure ONLY. Returns the underlying pg.Pool so spec setup can
   * borrow a long-lived PoolClient for BEGIN + SAVEPOINT isolation (see
   * `tests/db-transaction.ts`). Production code must inject `Db` via the `DB`
   * token and use `query`/`tx` — never touch the pool directly.
   *
   * @internal
   */
  unsafePool(): Pool {
    return this.pool;
  }
}
