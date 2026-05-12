import { Client } from 'pg';
import { runMigrations } from './run-migrations';

const TEST_DB = 'zt_test';

function postgresMaintenanceUrl(databaseUrl: string): string {
  const u = new URL(databaseUrl);
  u.pathname = '/postgres';
  return u.href;
}

function ztTestUrl(databaseUrl: string): string {
  const u = new URL(databaseUrl);
  u.pathname = `/${TEST_DB}`;
  return u.href;
}

/**
 * Jest globalSetup: ensure zt_test exists and apply migrations (D-02, D-03).
 * Skips when DATABASE_URL is unset (local runs without Postgres).
 */
export default async function globalSetup(): Promise<void> {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    // eslint-disable-next-line no-console
    console.warn('[jest globalSetup] DATABASE_URL not set — skipping zt_test + migrations');
    return;
  }

  try {
    const admin = new Client({
      connectionString: postgresMaintenanceUrl(databaseUrl),
    });
    await admin.connect();
    try {
      const { rowCount } = await admin.query('SELECT 1 FROM pg_database WHERE datname = $1', [
        TEST_DB,
      ]);
      if (!rowCount) {
        await admin.query(`CREATE DATABASE ${TEST_DB}`);
      }
    } finally {
      await admin.end();
    }

    const migrator = new Client({ connectionString: ztTestUrl(databaseUrl) });
    await migrator.connect();
    try {
      await runMigrations(migrator);
    } finally {
      await migrator.end();
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(
      '[jest globalSetup] Postgres unavailable — skipping zt_test + migrations (unit tests still run):',
      err instanceof Error ? err.message : err,
    );
  }
}
