# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development commands

### Setup
```bash
cp .env.example .env
```

### Run locally
```bash
./scripts/build.sh
./bin/wuwa-auth
```
- Service listens on `:${PORT:-8080}`.

### Runtime config
- Runtime config is loaded from `.env` at the repo root before normal environment variables.
- Real database credentials should live in `.env`, not in tracked source files.

### Build / lint / test status
- Build command: `./scripts/build.sh`
- End-to-end smoke test against a running service: `./scripts/e2e.sh`
- No dedicated lint configuration is present in the repository.
- Run Go tests with `go test ./...`.

## Architecture overview

This repository is a small Go-based auth service using a single PostgreSQL database. It exposes:
- Token-based JSON API routes under `/api`
- Server-rendered admin UI routes under `/admin`

Both surfaces share the same `users` table and permission logic.

### Application bootstrap and wiring
- `cmd/authd/main.go` is the service entrypoint.
- It loads `.env`, opens PostgreSQL, bootstraps schema/admin data, and mounts all HTTP routes in-process.
- Static assets for the admin UI are embedded from `cmd/authd/assets`.

### Persistence model
- PostgreSQL connection comes from `AUTH_DB_URL` or `DATABASE_URL`.
- The service creates a single `users` table (`token` is unique, `permissions`/`domains` are CSV text, `is_admin` flag, timestamps).
- Bootstrap inserts the first admin user only when no admin row exists.

### AuthN/AuthZ flow
- API authentication accepts `Authorization: Bearer ...` or `X-Token`.
- Admin UI authentication uses a signed session cookie.
- `manage` acts as a super-permission over `view` and `edit`.
- Token expiration and domain-scope checks are enforced centrally in the Go handlers.

### Route split
- `/api/login`, `/api/validate`, `/api/me`, and `/api/users` are served from `cmd/authd/main.go`.
- `/admin/login`, `/admin`, and `/admin/logout` are also implemented in the same Go binary.
- The admin UI also has a form-only autosave route at `POST /admin/users/{userID}/autosave`.

## Key behavioral details
- `permissions` are stored as CSV text in DB; route code normalizes before checks/persistence.
- `expires_at` is stored as ISO datetime text and validated on login/auth checks.
- In the admin UI, `expires_at`, remark, domains, and permissions autosave; name/token changes require the `更新名称和token` button.
- Admin autosave must preserve the existing DB name/token values instead of trusting hidden or edited form values for those fields.
- Updating admin-related env vars does not update an existing admin row automatically; bootstrap only creates the first admin when absent.
