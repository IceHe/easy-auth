#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent


def load_dotenv() -> None:
    env_path = ROOT_DIR / ".env"
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or key in os.environ:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ[key] = value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

    def http_error_302(self, req, fp, code, msg, headers):
        return fp

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def build_opener(with_cookies: bool = False, no_redirect: bool = False):
    handlers = [urllib.request.ProxyHandler({})]
    if with_cookies:
        handlers.append(urllib.request.HTTPCookieProcessor(CookieJar()))
    if no_redirect:
        handlers.append(NoRedirect())
    return urllib.request.build_opener(*handlers)


def load_admin_token_from_db() -> str:
    db_url = os.environ.get("AUTH_DB_URL") or os.environ.get("DATABASE_URL")
    if not db_url:
        return ""

    helper = ROOT_DIR / ".venv" / "bin" / "python"
    if not helper.exists():
        return ""

    query = (
        "import os, psycopg; "
        "conn = psycopg.connect(os.environ['AUTH_DB_URL']); "
        "row = conn.execute(\"select token from users where is_admin=true order by id limit 1\").fetchone(); "
        "print(row[0] if row else '')"
    )
    result = subprocess.run(
        [str(helper), "-c", query],
        env={**os.environ, "AUTH_DB_URL": db_url},
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def request_json(opener, method: str, url: str, *, payload=None, headers=None, expect_status=None):
    request_headers = dict(headers or {})
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    with opener.open(request, timeout=10) as response:
        body = response.read().decode("utf-8")
        if expect_status is not None and response.status != expect_status:
            raise AssertionError(f"expected {expect_status} from {method} {url}, got {response.status}: {body}")
        return response.status, json.loads(body)


def request_form(opener, method: str, url: str, *, form=None, headers=None, expect_status=None):
    request_headers = dict(headers or {})
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    try:
        response = opener.open(request, timeout=10)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        body = response.read().decode("utf-8")
        if expect_status is not None and response.status != expect_status:
            raise AssertionError(f"expected {expect_status} from {method} {url}, got {response.status}: {body}")
        return response.status, body, dict(response.headers)


def main() -> int:
    load_dotenv()

    base_url = os.environ.get("BASE_URL", "http://127.0.0.1:8080").rstrip("/")
    admin_token = os.environ.get("ADMIN_TOKEN") or os.environ.get("AUTH_ADMIN_TOKEN", "")
    if not admin_token:
        admin_token = load_admin_token_from_db()
    if not admin_token:
        raise SystemExit("ADMIN_TOKEN or AUTH_ADMIN_TOKEN is required")

    api = build_opener()
    admin = build_opener(with_cookies=True, no_redirect=True)

    stamp = int(time.time())
    test_name = f"e2e-{stamp}"
    test_token = f"e2e-token-{stamp}"
    test_domain = "e2e.example.com"
    test_user_id = None

    try:
        _, health = request_json(api, "GET", f"{base_url}/healthz", expect_status=200)
        assert health["ok"] is True

        try:
            _, login = request_json(
                api,
                "POST",
                f"{base_url}/api/login",
                payload={"token": admin_token},
                expect_status=200,
            )
        except urllib.error.HTTPError as exc:
            if exc.code != 401:
                raise
            fallback_token = load_admin_token_from_db()
            if not fallback_token or fallback_token == admin_token:
                raise
            admin_token = fallback_token
            _, login = request_json(
                api,
                "POST",
                f"{base_url}/api/login",
                payload={"token": admin_token},
                expect_status=200,
            )
        assert login["name"] == "admin"

        _, invalid = request_json(
            api,
            "POST",
            f"{base_url}/api/validate",
            payload={"token": "invalid-token"},
            expect_status=200,
        )
        assert invalid["reason"] == "invalid token"

        _, created = request_json(
            api,
            "POST",
            f"{base_url}/api/users",
            payload={
                "name": test_name,
                "token": test_token,
                "expires_at": "2099-12-31T23:59:59+00:00",
                "remark": "e2e",
                "permissions": ["view", "edit"],
                "domains": [test_domain],
            },
            headers={"Authorization": f"Bearer {admin_token}"},
            expect_status=201,
        )
        assert created["ok"] is True

        _, users = request_json(
            api,
            "GET",
            f"{base_url}/api/users",
            headers={"Authorization": f"Bearer {admin_token}"},
            expect_status=200,
        )
        for item in users:
            if item["token"] == test_token:
                test_user_id = item["id"]
                break
        if test_user_id is None:
            raise AssertionError("created user not found in /api/users")

        _, validated = request_json(
            api,
            "POST",
            f"{base_url}/api/validate",
            payload={"token": test_token, "permission": "edit", "domain": test_domain},
            expect_status=200,
        )
        assert validated["valid"] is True

        status, _, headers = request_form(
            admin,
            "POST",
            f"{base_url}/admin/login",
            form={"token": admin_token},
            expect_status=303,
        )
        assert status == 303
        assert headers.get("Location") == "/admin"

        page_status, page_body, _ = request_form(admin, "GET", f"{base_url}/admin", expect_status=200)
        assert page_status == 200
        assert "鉴权管理后台" in page_body

        _, deleted = request_json(
            api,
            "DELETE",
            f"{base_url}/api/users/{test_user_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
            expect_status=200,
        )
        assert deleted["ok"] is True
        test_user_id = None
        print("e2e ok")
        return 0
    finally:
        if test_user_id is not None:
            try:
                request_json(
                    api,
                    "DELETE",
                    f"{base_url}/api/users/{test_user_id}",
                    headers={"Authorization": f"Bearer {admin_token}"},
                    expect_status=200,
                )
            except Exception:
                pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"e2e failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
