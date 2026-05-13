import type { PoolClient, QueryResult } from 'pg';

/**
 * Db port — typed abstraction over the shared pg.Pool owned by DbService.
 *
 * Consumers inject this via `@Inject(DB)` and never touch `pg.Pool` directly.
 * The `tx` callback receives a `PoolClient` bound to a single BEGIN/COMMIT
 * transaction; ROLLBACK + rethrow happens automatically on throw.
 */
export interface Db {
  query<R = unknown>(sql: string, params?: ReadonlyArray<unknown>): Promise<QueryResult<R>>;
  tx<R>(fn: (client: PoolClient) => Promise<R>): Promise<R>;
}

/** Injection token for the shared Db instance. */
export const DB = Symbol('DB');
