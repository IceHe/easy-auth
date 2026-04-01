from typing import Any, Generator

import psycopg
from psycopg.rows import dict_row

from .config import ADMIN_EXPIRES_AT, ADMIN_NAME, ADMIN_TOKEN, DATABASE_URL
from .users import now_iso


def open_db():
    if not DATABASE_URL:
        raise RuntimeError("AUTH_DB_URL or DATABASE_URL is required; configure it in .env or the environment")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def get_db() -> Generator[Any, None, None]:
    db = open_db()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db():
    db = open_db()
    try:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                remark TEXT NOT NULL DEFAULT '',
                permissions TEXT NOT NULL,
                domains TEXT NOT NULL DEFAULT '*',
                is_admin BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS remark TEXT NOT NULL DEFAULT ''")
        db.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS domains TEXT NOT NULL DEFAULT '*'")
        db.commit()
    finally:
        db.close()


def ensure_admin_user():
    db = open_db()
    try:
        row = db.execute("SELECT id FROM users WHERE is_admin = TRUE LIMIT 1").fetchone()
        if row:
            return

        ts = now_iso()
        db.execute(
            """
            INSERT INTO users (name, token, expires_at, remark, permissions, domains, is_admin, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, TRUE, %s, %s)
            """,
            (ADMIN_NAME, ADMIN_TOKEN, ADMIN_EXPIRES_AT, "", "manage,view,edit", "*", ts, ts),
        )
        db.commit()
    finally:
        db.close()


def find_user_by_token(db, token: str):
    return db.execute("SELECT * FROM users WHERE token = %s", (token,)).fetchone()


def find_user_by_id(db, user_id: int):
    return db.execute("SELECT * FROM users WHERE id = %s", (user_id,)).fetchone()


def is_unique_violation(exc: Exception) -> bool:
    if getattr(exc, "sqlstate", None) == "23505":
        return True
    cause = getattr(exc, "__cause__", None)
    return bool(cause and getattr(cause, "sqlstate", None) == "23505")
