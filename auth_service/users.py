from datetime import datetime, timezone
from urllib.parse import urlparse


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_permissions(raw):
    allowed = {"manage", "view", "edit"}
    if isinstance(raw, str):
        items = [x.strip().lower() for x in raw.split(",") if x.strip()]
    else:
        items = [str(x).strip().lower() for x in raw if str(x).strip()]
    items = sorted(set(x for x in items if x in allowed))
    return items


def _normalize_domain_item(value) -> str:
    item = str(value).strip().lower()
    if not item:
        return ""
    if item == "*":
        return "*"
    if "://" in item:
        item = urlparse(item).netloc.strip().lower() or urlparse(item).path.strip().lower()
    item = item.split("/", 1)[0].strip()
    return item


def normalize_domains(raw):
    if isinstance(raw, str):
        parts = [x for x in raw.split(",")]
    else:
        parts = [str(x) for x in raw]

    items = []
    for part in parts:
        normalized = _normalize_domain_item(part)
        if not normalized:
            continue
        if normalized == "*":
            return ["*"]
        items.append(normalized)
    return sorted(set(items))


def has_permission(user, perm: str) -> bool:
    perms = normalize_permissions(user["permissions"] or "")
    return "manage" in perms or perm in perms


def has_domain_access(user, domain: str) -> bool:
    domains = normalize_domains(user.get("domains") or "*")
    normalized = _normalize_domain_item(domain)
    if not normalized:
        return False
    return "*" in domains or normalized in domains


def validate_admin_update(user, permissions, expires_at: str) -> str | None:
    if not bool(user["is_admin"]):
        return None
    if "manage" not in permissions:
        return "admin user must keep manage permission"
    if parse_iso(expires_at) < now_utc():
        return "admin user cannot be expired"
    return None
