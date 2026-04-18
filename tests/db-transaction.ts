import type { PoolClient } from 'pg';

/**
 * Per-suite outer transaction (D-01). Call once in beforeAll.
 */
export async function beginSuiteTransaction(client: PoolClient): Promise<void> {
  await client.query('BEGIN');
}

/**
 * Per-test SAVEPOINT. Call in beforeEach after beginSuiteTransaction.
 */
export async function savepoint(client: PoolClient, name: string): Promise<void> {
  await client.query(`SAVEPOINT ${validateSavepointName(name)}`);
}

/**
 * Undo work since the named SAVEPOINT. Call in afterEach.
 */
export async function rollbackToSavepoint(
  client: PoolClient,
  name: string,
): Promise<void> {
  await client.query(`ROLLBACK TO SAVEPOINT ${validateSavepointName(name)}`);
}

function validateSavepointName(name: string): string {
  if (!/^[a-z][a-z0-9_]*$/i.test(name)) {
    throw new Error(`Invalid SAVEPOINT identifier: ${name}`);
  }
  return name;
}
