import * as fs from 'fs';
import * as path from 'path';
import type { Client } from 'pg';

/**
 * Apply all sql/migrations/*.sql files in lexicographic order (D-03).
 */
export async function runMigrations(client: Client): Promise<void> {
  const dir = path.join(__dirname, '..', 'sql', 'migrations');
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .sort();
  for (const file of files) {
    const full = path.join(dir, file);
    const sql = fs.readFileSync(full, 'utf8');
    await client.query(sql);
  }
}
