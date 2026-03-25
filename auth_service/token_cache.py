from __future__ import annotations

from collections import OrderedDict
from threading import RLock
from time import monotonic
from typing import Any

from .config import AUTH_TOKEN_CACHE_ENABLED, AUTH_TOKEN_CACHE_MAX_SIZE, AUTH_TOKEN_CACHE_TTL_SECONDS
from .db import find_user_by_token
from .users import now_utc, parse_iso


_CACHE_LOCK = RLock()
_CACHE: OrderedDict[str, tuple[dict[str, Any], float]] = OrderedDict()


def _to_user_dict(user: dict[str, Any]) -> dict[str, Any]:
    if isinstance(user, dict):
        return dict(user)
    return dict(user)


def _evict_if_needed() -> None:
    while len(_CACHE) > AUTH_TOKEN_CACHE_MAX_SIZE:
        _CACHE.popitem(last=False)


def get_token_user(token: str) -> dict[str, Any] | None:
    if not AUTH_TOKEN_CACHE_ENABLED:
        return None

    with _CACHE_LOCK:
        entry = _CACHE.get(token)
        if not entry:
            return None

        user, cached_at = entry
        if monotonic() - cached_at > AUTH_TOKEN_CACHE_TTL_SECONDS:
            _CACHE.pop(token, None)
            return None

        try:
            if parse_iso(user["expires_at"]) < now_utc():
                _CACHE.pop(token, None)
                return user
        except Exception:
            _CACHE.pop(token, None)
            return None

        _CACHE.move_to_end(token)
        return dict(user)


def set_token_user(user: dict[str, Any]) -> None:
    if not AUTH_TOKEN_CACHE_ENABLED:
        return

    user_dict = _to_user_dict(user)
    token = str(user_dict.get("token", "")).strip()
    if not token:
        return

    with _CACHE_LOCK:
        _CACHE[token] = (user_dict, monotonic())
        _CACHE.move_to_end(token)
        _evict_if_needed()


def invalidate_token(token: str) -> None:
    if not AUTH_TOKEN_CACHE_ENABLED:
        return

    with _CACHE_LOCK:
        _CACHE.pop(token, None)


def invalidate_tokens(tokens: list[str]) -> None:
    if not AUTH_TOKEN_CACHE_ENABLED:
        return

    with _CACHE_LOCK:
        for token in tokens:
            _CACHE.pop(token, None)


def get_or_load_user_by_token(db, token: str):
    token = token.strip()
    if not token:
        return None

    cached_user = get_token_user(token)
    if cached_user is not None:
        return cached_user

    user = find_user_by_token(db, token)
    if user:
        set_token_user(user)
    return user
