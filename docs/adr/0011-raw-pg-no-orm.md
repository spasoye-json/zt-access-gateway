# Raw `pg` driver, no ORM

All persistence (trust signals, audit logs, MFA state, user secrets) uses the raw `pg` client with explicit, prepared SQL — no TypeORM/Prisma/Sequelize. The hot paths are high-frequency, narrow inserts/queries (trust + audit on every allowed request) where an ORM's mapping layer is overhead, not leverage, and the schema is small enough that migrations-as-a-framework-feature isn't worth the dependency and lock-in.

## Considered options

- **TypeORM/Prisma (rejected):** type-mapped entities and migration tooling, at the cost of a heavy dependency on every hot-path write and another abstraction to reason about under load.

## Consequences

- SQL is explicit and visible at the call site; injection is guarded by prepared statements, not an ORM.
- Schema changes are managed manually rather than by an ORM migration runner.
