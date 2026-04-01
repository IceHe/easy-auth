from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from starlette.middleware.sessions import SessionMiddleware

from .config import SECRET_KEY
from .db import ensure_admin_user, init_db
from .routes_admin import admin_router
from .routes_api import api_router

FAVICON_PATH = Path(__file__).resolve().parent / "assets" / "favicon.ico"
FAVICON_SVG_PATH = Path(__file__).resolve().parent / "assets" / "favicon.svg"


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

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon():
        return FileResponse(
            FAVICON_PATH,
            media_type="image/x-icon",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @app.get("/favicon.svg", include_in_schema=False)
    def favicon_svg():
        return FileResponse(
            FAVICON_SVG_PATH,
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    return app
