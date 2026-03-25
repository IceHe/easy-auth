from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from .config import SECRET_KEY
from .db import ensure_admin_user, init_db
from .routes_admin import admin_router
from .routes_api import api_router


def bootstrap():
    init_db()
    ensure_admin_user()


def create_app():
    app = FastAPI(title="Simple Auth Service")
    app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

    app.include_router(api_router)
    app.include_router(admin_router)

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    return app
