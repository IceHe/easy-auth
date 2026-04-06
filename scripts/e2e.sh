#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

load_dotenv() {
  local env_file="$ROOT_DIR/.env"
  if [[ ! -f "$env_file" ]]; then
    return
  fi

  set -a
  # shellcheck disable=SC1090
  source "$env_file"
  set +a
}

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local message="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "e2e failed: $message" >&2
    exit 1
  fi
}

load_dotenv

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
BASE_URL="${BASE_URL%/}"
ADMIN_TOKEN="${ADMIN_TOKEN:-${AUTH_ADMIN_TOKEN:-}}"

if [[ -z "$ADMIN_TOKEN" ]]; then
  echo "e2e failed: ADMIN_TOKEN or AUTH_ADMIN_TOKEN is required" >&2
  exit 1
fi

stamp="$(date +%s)"
test_name="e2e-$stamp"
test_token="e2e-token-$stamp"
test_domain="e2e.example.com"
cookie_jar="$(mktemp)"
cleanup() {
  rm -f "$cookie_jar"
}
trap cleanup EXIT

health_body="$(curl -fsS "$BASE_URL/healthz")"
assert_contains "$health_body" '"ok":true' "GET /healthz did not return ok=true"

login_body="$(curl -fsS \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$ADMIN_TOKEN\"}" \
  "$BASE_URL/api/login")"
assert_contains "$login_body" '"name":"admin"' "POST /api/login did not authenticate the admin token"

invalid_body="$(curl -fsS \
  -H 'Content-Type: application/json' \
  -d '{"token":"invalid-token"}' \
  "$BASE_URL/api/validate")"
assert_contains "$invalid_body" '"reason":"invalid token"' "POST /api/validate did not reject an invalid token"

create_status="$(curl -sS -o /tmp/wuwa-auth-e2e-create.json -w '%{http_code}' \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"$test_name\",\"token\":\"$test_token\",\"expires_at\":\"2099-12-31T23:59:59+00:00\",\"remark\":\"e2e\",\"permissions\":[\"view\",\"edit\"],\"domains\":[\"$test_domain\"]}" \
  "$BASE_URL/api/users")"
create_body="$(cat /tmp/wuwa-auth-e2e-create.json)"
rm -f /tmp/wuwa-auth-e2e-create.json
if [[ "$create_status" != "201" ]]; then
  echo "e2e failed: expected 201 from POST /api/users, got $create_status: $create_body" >&2
  exit 1
fi
assert_contains "$create_body" '"ok":true' "POST /api/users did not return ok=true"

users_body="$(curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" "$BASE_URL/api/users")"
assert_contains "$users_body" "\"token\":\"$test_token\"" "GET /api/users did not return the created user"
test_user_id="$(printf '%s' "$users_body" | grep -o "\"id\":[0-9][0-9]*,\"name\":\"$test_name\"" | head -n1 | sed 's/"id":\([0-9][0-9]*\).*/\1/')"
if [[ -z "$test_user_id" ]]; then
  echo "e2e failed: created user id not found in GET /api/users response" >&2
  exit 1
fi

validated_body="$(curl -fsS \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$test_token\",\"permission\":\"edit\",\"domain\":\"$test_domain\"}" \
  "$BASE_URL/api/validate")"
assert_contains "$validated_body" '"valid":true' "POST /api/validate did not accept the created token"

admin_status="$(curl -sS -o /tmp/wuwa-auth-e2e-admin-login.html -w '%{http_code}' \
  -c "$cookie_jar" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "token=$ADMIN_TOKEN" \
  "$BASE_URL/admin/login")"
rm -f /tmp/wuwa-auth-e2e-admin-login.html
if [[ "$admin_status" != "303" ]]; then
  echo "e2e failed: expected 303 from POST /admin/login, got $admin_status" >&2
  exit 1
fi

admin_body="$(curl -fsS -b "$cookie_jar" "$BASE_URL/admin")"
assert_contains "$admin_body" '鉴权管理后台' "GET /admin did not render the admin dashboard"

delete_status="$(curl -sS -o /tmp/wuwa-auth-e2e-delete.json -w '%{http_code}' \
  -X DELETE \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  "$BASE_URL/api/users/$test_user_id")"
delete_body="$(cat /tmp/wuwa-auth-e2e-delete.json)"
rm -f /tmp/wuwa-auth-e2e-delete.json
if [[ "$delete_status" != "200" ]]; then
  echo "e2e failed: expected 200 from DELETE /api/users/$test_user_id, got $delete_status: $delete_body" >&2
  exit 1
fi
assert_contains "$delete_body" '"ok":true' "DELETE /api/users/{id} did not return ok=true"

echo "e2e ok"
