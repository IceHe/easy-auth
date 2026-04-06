from __future__ import annotations

from collections import defaultdict, deque
from ipaddress import ip_address
from math import ceil
from threading import RLock
from time import monotonic

from fastapi import Request

from .config import AUTH_RATE_LIMIT_ENABLED, AUTH_RATE_LIMIT_IP_WHITELIST, AUTH_RATE_LIMIT_TRUST_PROXY


_LOCK = RLock()
_HITS: dict[tuple[str, str], deque[float]] = defaultdict(deque)
_CLEANUP_EVERY = 256
_request_count = 0


def get_client_ip(request: Request) -> str:
    if AUTH_RATE_LIMIT_TRUST_PROXY:
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            client_ip = forwarded_for.split(",", 1)[0].strip()
            if client_ip:
                return client_ip

    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def is_rate_limit_exempt(client_ip: str) -> bool:
    try:
        parsed_ip = ip_address(client_ip)
    except ValueError:
        return False
    return any(parsed_ip in network for network in AUTH_RATE_LIMIT_IP_WHITELIST)


def check_rate_limit(request: Request, scope: str, max_requests: int, window_seconds: int) -> int | None:
    if not AUTH_RATE_LIMIT_ENABLED or max_requests <= 0 or window_seconds <= 0:
        return None

    client_ip = get_client_ip(request)
    if is_rate_limit_exempt(client_ip):
        return None

    key = (scope, client_ip)
    now = monotonic()

    with _LOCK:
        global _request_count
        _request_count += 1
        if _request_count % _CLEANUP_EVERY == 0:
            _cleanup_stale_entries(now, window_seconds)

        bucket = _HITS[key]
        _trim_bucket(bucket, now, window_seconds)
        if len(bucket) >= max_requests:
            retry_after = max(1, ceil(window_seconds - (now - bucket[0])))
            return retry_after

        bucket.append(now)
        return None


def _trim_bucket(bucket: deque[float], now: float, window_seconds: int) -> None:
    threshold = now - window_seconds
    while bucket and bucket[0] <= threshold:
        bucket.popleft()


def _cleanup_stale_entries(now: float, default_window_seconds: int) -> None:
    stale_keys: list[tuple[str, str]] = []
    for key, bucket in _HITS.items():
        _trim_bucket(bucket, now, default_window_seconds)
        if not bucket:
            stale_keys.append(key)

    for key in stale_keys:
        _HITS.pop(key, None)
