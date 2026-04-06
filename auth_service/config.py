import os
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path


def _load_dotenv() -> None:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


_load_dotenv()


DATABASE_URL = os.getenv("AUTH_DB_URL") or os.getenv("DATABASE_URL")
ADMIN_NAME = os.getenv("AUTH_ADMIN_NAME", "admin")
ADMIN_TOKEN = os.getenv("AUTH_ADMIN_TOKEN", "change-me-admin-token")
ADMIN_EXPIRES_AT = os.getenv("AUTH_ADMIN_EXPIRES_AT", "2099-12-31T23:59:59+00:00")
SECRET_KEY = os.getenv("AUTH_SECRET_KEY", "change-me-session-secret")


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _env_ip_networks(name: str, default: str) -> tuple[IPv4Network | IPv6Network, ...]:
    raw_value = os.getenv(name, default)
    networks: list[IPv4Network | IPv6Network] = []
    for item in raw_value.split(","):
        value = item.strip()
        if not value:
            continue
        try:
            networks.append(ip_network(value, strict=False))
        except ValueError:
            continue
    return tuple(networks)


AUTH_TOKEN_CACHE_ENABLED = _env_bool("AUTH_TOKEN_CACHE_ENABLED", True)
AUTH_TOKEN_CACHE_TTL_SECONDS = int(os.getenv("AUTH_TOKEN_CACHE_TTL_SECONDS", "10"))
AUTH_TOKEN_CACHE_MAX_SIZE = int(os.getenv("AUTH_TOKEN_CACHE_MAX_SIZE", "2000"))
AUTH_RATE_LIMIT_ENABLED = _env_bool("AUTH_RATE_LIMIT_ENABLED", True)
AUTH_RATE_LIMIT_TRUST_PROXY = _env_bool("AUTH_RATE_LIMIT_TRUST_PROXY", False)
AUTH_RATE_LIMIT_IP_WHITELIST = _env_ip_networks("AUTH_RATE_LIMIT_IP_WHITELIST", "127.0.0.1,::1")
AUTH_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("AUTH_RATE_LIMIT_WINDOW_SECONDS", "60"))
AUTH_RATE_LIMIT_API_LOGIN_MAX_REQUESTS = int(os.getenv("AUTH_RATE_LIMIT_API_LOGIN_MAX_REQUESTS", "20"))
AUTH_RATE_LIMIT_API_VALIDATE_MAX_REQUESTS = int(os.getenv("AUTH_RATE_LIMIT_API_VALIDATE_MAX_REQUESTS", "60"))
AUTH_RATE_LIMIT_ADMIN_LOGIN_MAX_REQUESTS = int(os.getenv("AUTH_RATE_LIMIT_ADMIN_LOGIN_MAX_REQUESTS", "10"))
