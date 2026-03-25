from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, HTTPException, Request, status

from .db import find_user_by_id, get_db
from .token_cache import get_or_load_user_by_token
from .users import has_permission, parse_iso


def _validate_not_expired(user: dict[str, Any]):
    if parse_iso(user["expires_at"]) < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token expired")


def get_current_user(permission: str = "view"):
    def dep(request: Request, db=Depends(get_db)):
        auth = request.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip() if auth else ""
        if not token:
            token = request.headers.get("X-Token", "").strip()
        if not token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing token")

        user = get_or_load_user_by_token(db, token)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")

        _validate_not_expired(user)
        if not has_permission(user, permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
        return user

    return dep


def require_admin_session(request: Request, db=Depends(get_db)):
    uid = request.session.get("user_id")
    if not uid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="login required")
    user = find_user_by_id(db, uid)
    if not user:
        request.session.clear()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="login required")

    _validate_not_expired(user)
    if not has_permission(user, "manage"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    return user
