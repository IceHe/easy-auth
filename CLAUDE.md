# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development commands

### Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### Run locally
```bash
python app.py
```
- Service starts via Uvicorn on `0.0.0.0:${PORT:-8080}`.

### Runtime config
- Runtime config is loaded from `.env` at the repo root before normal environment variables.
- Real database credentials should live in `.env`, not in tracked source files.

### Build / lint / test status
- No build configuration file is present (`Makefile`, `pyproject.toml`, `setup.cfg`, `tox.ini` are absent).
- No lint tool configuration is present.
- No project test suite/config is present in the repository.
- There is currently no repo-defined command for running all tests or a single test.

## Architecture overview

This repository is a small FastAPI-based auth service using a single PostgreSQL database. It exposes:
- Token-based JSON API routes under `/api`
- Server-rendered admin UI routes under `/admin`

Both surfaces share the same `users` table and permission logic.

### Application bootstrap and wiring
- `app.py` is the process entrypoint.
  - Calls `bootstrap()` before app creation.
  - Creates the app via `create_app()` and runs Uvicorn.
- `auth_service/app_factory.py`
  - `bootstrap()` initializes schema and ensures an admin user exists.
  - `create_app()` configures `SessionMiddleware`, includes API/admin routers, and defines `/healthz`.
- `auth_service/__init__.py` re-exports `bootstrap` and `create_app`.

### Persistence model
- `auth_service/db.py`
  - Uses PostgreSQL at `AUTH_DB_URL`.
  - Creates a single `users` table (`token` is unique, `permissions` is comma-separated text, `is_admin` flag, timestamps).
  - `ensure_admin_user()` inserts initial admin only when no admin row exists.
- `auth_service/config.py` holds env-driven runtime config:
  - `AUTH_DB_URL`, `AUTH_ADMIN_NAME`, `AUTH_ADMIN_TOKEN`, `AUTH_ADMIN_EXPIRES_AT`, `AUTH_SECRET_KEY`.

### AuthN/AuthZ flow
- `auth_service/decorators.py`
  - API authentication reads token from `Authorization: Bearer ...` or `X-Token`.
  - Admin UI authentication uses session cookie (`request.session["user_id"]`).
  - Token expiration is enforced centrally.
- `auth_service/users.py`
  - Normalizes permissions to `manage`, `view`, `edit`.
  - `manage` acts as a super-permission.
  - Handles UTC timestamp generation/parsing (`now_iso`, `parse_iso`).

### Route split
- `auth_service/routes_api.py`
  - Machine-facing endpoints: `/api/login`, `/api/validate`, `/api/me`, and user management endpoints.
  - Uses FastAPI dependencies (`Depends(get_db)`, `Depends(get_current_user(...))`).
- `auth_service/routes_admin.py`
  - HTML login + admin console with form-based create/update operations.
  - Uses shared PostgreSQL connections and session checks (`get_admin_from_session`).

## Key behavioral details
- `permissions` are stored as CSV text in DB; route code normalizes before checks/persistence.
- `expires_at` is stored as ISO datetime text and validated on login/auth checks.
- Updating admin-related env vars does not update an existing admin row automatically; bootstrap only creates the first admin when absent.
