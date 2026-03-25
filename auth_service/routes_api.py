from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

import psycopg

from .db import find_user_by_id, get_db, is_unique_violation
from .decorators import get_current_user
from .token_cache import get_or_load_user_by_token, invalidate_tokens
from .users import has_permission, normalize_permissions, now_iso, now_utc, parse_iso, validate_admin_update


api_router = APIRouter(prefix="/api", tags=["api"])


class LoginRequest(BaseModel):
    token: str


class ValidateTokenRequest(BaseModel):
    token: str
    permission: str | None = None


class UserPayload(BaseModel):
    name: str
    token: str
    expires_at: str
    remark: str = ""
    permissions: List[str]


class UserUpdatePayload(BaseModel):
    name: str
    token: str
    expires_at: str
    remark: str = ""
    permissions: List[str]


@api_router.post("/login")
def api_login(payload: LoginRequest, db=Depends(get_db)):
    token = payload.token.strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="token is required")

    user = get_or_load_user_by_token(db, token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")
    if parse_iso(user["expires_at"]) < now_utc():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="token expired")

    return user_public(user)


@api_router.post("/validate")
def api_validate(payload: ValidateTokenRequest, db=Depends(get_db)):
    token = payload.token.strip()
    permission = (payload.permission or "").strip().lower()
    if not token:
        return {"valid": False, "permissions": [], "reason": "token is required"}

    user = get_or_load_user_by_token(db, token)
    if not user:
        return {"valid": False, "permissions": [], "reason": "invalid token"}
    if parse_iso(user["expires_at"]) < now_utc():
        return {"valid": False, "permissions": [], "reason": "token expired"}

    permissions = normalize_permissions(user["permissions"])
    if permission and permission not in {"manage", "view", "edit"}:
        return {"valid": False, "permissions": permissions, "reason": "invalid permission"}
    if permission and not has_permission(user, permission):
        return {"valid": False, "permissions": permissions, "reason": "forbidden"}

    return {
        "valid": True,
        "id": user["id"],
        "permissions": permissions,
    }


@api_router.get("/me")
def api_me(current_user=Depends(get_current_user("view"))):
    return user_public(current_user)


@api_router.get("/users")
def api_users_list(_current_user=Depends(get_current_user("manage")), db=Depends(get_db)):
    rows = db.execute(
        "SELECT id, name, expires_at, remark, token, permissions, created_at, updated_at, is_admin FROM users ORDER BY id ASC"
    ).fetchall()
    return [user_full(x) for x in rows]


@api_router.post("/users", status_code=status.HTTP_201_CREATED)
def api_users_create(payload: UserPayload, _current_user=Depends(get_current_user("manage")), db=Depends(get_db)):
    name = payload.name.strip()
    token = payload.token.strip()
    expires_at = payload.expires_at.strip()
    remark = payload.remark.strip()
    permissions = normalize_permissions(payload.permissions)

    if not name or not token or not expires_at or not permissions:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="name/token/expires_at/permissions are required")
    try:
        parse_iso(expires_at)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expires_at must be valid ISO datetime") from exc

    ts = now_iso()
    try:
        db.execute(
            """
            INSERT INTO users (name, token, expires_at, remark, permissions, is_admin, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, FALSE, %s, %s)
            """,
            (name, token, expires_at, remark, ",".join(permissions), ts, ts),
        )
        db.commit()
        invalidate_tokens([token])
    except psycopg.IntegrityError as exc:
        if not is_unique_violation(exc):
            raise
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="token already exists") from exc
    return {"ok": True}


@api_router.put("/users/{user_id}")
def api_users_update(user_id: int, payload: UserUpdatePayload, _current_user=Depends(get_current_user("manage")), db=Depends(get_db)):
    user = find_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")

    name = payload.name.strip()
    token = payload.token.strip()
    expires_at = payload.expires_at.strip()
    remark = payload.remark.strip()
    permissions = normalize_permissions(payload.permissions)

    if not name or not token or not expires_at or not permissions:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="name/token/expires_at/permissions are required")

    try:
        parse_iso(expires_at)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expires_at must be valid ISO datetime") from exc
    admin_error = validate_admin_update(user, permissions, expires_at)
    if admin_error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=admin_error)

    try:
        db.execute(
            """
            UPDATE users SET name = %s, token = %s, expires_at = %s, remark = %s, permissions = %s, updated_at = %s
            WHERE id = %s
            """,
            (name, token, expires_at, remark, ",".join(permissions), now_iso(), user_id),
        )
        db.commit()
        invalidate_tokens([str(user["token"]), token])
    except psycopg.IntegrityError as exc:
        if not is_unique_violation(exc):
            raise
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="token already exists") from exc
    return {"ok": True}


@api_router.delete("/users/{user_id}")
def api_users_delete(user_id: int, _current_user=Depends(get_current_user("manage")), db=Depends(get_db)):
    user = find_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
    if bool(user["is_admin"]):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="admin user cannot be deleted")

    db.execute("DELETE FROM users WHERE id = %s", (user_id,))
    db.commit()
    invalidate_tokens([str(user["token"])])
    return {"ok": True}


def user_public(user):
    return {
        "id": user["id"],
        "name": user["name"],
        "expires_at": user["expires_at"],
        "remark": user["remark"],
        "permissions": normalize_permissions(user["permissions"]),
        "created_at": user["created_at"],
        "updated_at": user["updated_at"],
    }


def user_full(user):
    data = user_public(user)
    data["token"] = user["token"]
    data["is_admin"] = bool(user["is_admin"])
    return data
