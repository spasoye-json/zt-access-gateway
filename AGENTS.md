# Repository Guidelines

## Project Structure & Module Organization

- `src/` holds the NestJS gateway code (`auth/`, `gateway/`, `policy/`, `trust-score/`, `proxy/`, `audit/`, `metrics/`, `shared/`).
- `microservices/` contains demo downstream services (users/orders/permissions).
- `policy/` stores the Casbin model and policy CSV.
- `tests/` includes `unit/` and `integration/` suites.
- `docs/` has architecture and codebase walkthroughs.
- Docker assets live in `Dockerfile`, `Dockerfile.microservice`, and `docker-compose.yml`.

## Build, Test, and Development Commands

- `npm run start:dev` — run the gateway with hot reload.
- `npm run build` then `npm run start:prod` — build TypeScript and run `dist/main`.
- `npm run lint` — run ESLint with auto-fix enabled.
- `npm test` — run Jest unit + integration suites.
- `npm run test:watch` — re-run Jest on file changes.
- `npm run test:cov` — generate coverage in `artifacts/coverage/`.
- `npm run test:e2e` — run integration tests with `tests/integration/*`.
- `docker-compose up --build` — start the full stack (gateway, demo services, observability).

## Coding Style & Naming Conventions

- TypeScript with Prettier defaults: 2-space indentation, single quotes, trailing commas, semicolons, 100-char line width.
- ESLint uses `@typescript-eslint` + `prettier` rules; keep code lint-clean.
- Follow NestJS file naming: `*.module.ts`, `*.service.ts`, `*.controller.ts`.
- Tests should be named `*.spec.ts`.

## Testing Guidelines

- Jest is the test runner; tests live in `src/` and `tests/` and must match `*.spec.ts`.
- Unit tests live under `tests/unit/`; integration tests under `tests/integration/`.
- If a test spins up the app or binds a port, keep it in integration and guard for CI constraints.

## Commit & Pull Request Guidelines

- Commit messages follow Conventional Commits patterns such as `feat:`, `docs:`, `refactor:`.
- PRs should include: a concise summary, linked issues (if any), test commands run, and config changes.
- Update `docs/STARTUP_GUIDE.md` or `docs/CODEBASE.md` when behavior, config, or architecture changes.

## Security & Configuration Tips

- Use `.env` for local settings; common variables include `JWT_*`, `DATABASE_URL`, `SERVICE_REGISTRY`, and `MTLS_*`.
- Run `./create-certs.sh` before local mTLS testing.
- Only set `ALLOW_INSECURE_MICROSERVICE_HTTP=true` in development.
