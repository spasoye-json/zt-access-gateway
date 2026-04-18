# Test harness notes

## Postgres and `zt_test`

Phase 4+ database integration tests expect:

- Docker Compose Postgres (or any local Postgres) reachable via `DATABASE_URL`
- Jest `globalSetup` (`tests/setup-db.ts`) creates database **`zt_test`** on the same server if it does not exist, then applies `sql/migrations/*.sql` in sorted order

If `DATABASE_URL` is not set, global setup skips migrations and DB specs that guard on `DATABASE_URL` are skipped.

## Jest workers

Run DB suites with a single worker so one connection / transaction scope stays consistent:

```bash
npx jest --runInBand
```

Example:

```bash
npx jest src/trust-score/__tests__/trust-telemetry.repository.spec.ts --runInBand --forceExit
```
