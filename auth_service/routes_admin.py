import html
import secrets
import string
from datetime import datetime, timedelta, timezone

import psycopg
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

from .config import AUTH_RATE_LIMIT_ADMIN_LOGIN_MAX_REQUESTS, AUTH_RATE_LIMIT_WINDOW_SECONDS
from .db import find_user_by_id, get_db, is_unique_violation, open_db
from .rate_limit import check_rate_limit
from .token_cache import get_or_load_user_by_token, invalidate_tokens
from .users import has_permission, normalize_domains, normalize_permissions, now_iso, now_utc, parse_iso, validate_admin_update


admin_router = APIRouter(prefix="/admin", tags=["admin"])
FAVICON_LINK_HTML = (
    '<link rel="icon" type="image/svg+xml" href="/favicon.svg">'
    '<link rel="alternate icon" type="image/x-icon" href="/favicon.ico">'
)


QUICK_ROLE_PERMISSIONS = {
    "viewer": ["view"],
    "editor": ["view", "edit"],
}


def generate_quick_name() -> str:
    prefix = "".join(secrets.choice(string.ascii_lowercase) for _ in range(6))
    ts = now_utc().strftime("%Y%m%d%H%M%S")
    return f"{prefix}{ts}"


def generate_quick_expires_at() -> str:
    return (now_utc() + timedelta(days=7)).isoformat()


def generate_quick_token() -> str:
    return secrets.token_hex(32)


def normalize_admin_form_expires_at(raw: str) -> str:
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return dt.astimezone(timezone.utc).isoformat()


def to_datetime_local_value(raw: str) -> str:
    return parse_iso(raw).astimezone().strftime("%Y-%m-%dT%H:%M:%S")


def format_display_timestamp(raw: str) -> str:
    return parse_iso(raw).astimezone().isoformat(timespec="seconds").replace("T", " ")


@admin_router.get("/login")
def login_page(request: Request):
    error = str(request.query_params.get("error", "")).strip()
    error_map = {
        "invalid": "token 无效",
        "expired": "token 已过期",
        "forbidden": "仅管理员可登录后台",
        "logged_out": "已退出登录",
        "rate_limited": "请求过多，请稍后再试",
    }
    error_text = error_map.get(error, "")
    error_html = f"<p style='color:#b91c1c'>{html.escape(error_text)}</p>" if error_text else ""
    return HTMLResponse(
        f"""
        <!doctype html>
        <html lang="zh">
        <head><meta charset="utf-8">{FAVICON_LINK_HTML}<title>鉴权后台登录</title></head>
        <body>
          <h1>鉴权后台登录</h1>
          {error_html}
          <form id="login-form" method="post" action="/admin/login">
            <label>Token: <input id="token" type="password" name="token" style="width: 320px;" autocomplete="current-password" autocapitalize="off" autocorrect="off" spellcheck="false" required></label>
            <button type="submit">登录</button>
          </form>
          <script>
            (function () {{
              const form = document.getElementById("login-form");
              const tokenInput = document.getElementById("token");
              const savedTokenKey = "auth_admin_token";
              const error = new URLSearchParams(window.location.search).get("error") || "";

              if (error === "invalid" || error === "expired" || error === "forbidden" || error === "logged_out") {{
                localStorage.removeItem(savedTokenKey);
              }}

              const savedToken = localStorage.getItem(savedTokenKey) || "";
              if (savedToken) {{
                tokenInput.value = savedToken;
                if (!error) {{
                  form.requestSubmit();
                }}
              }}

              form.addEventListener("submit", function () {{
                const token = tokenInput.value.trim();
                if (token) {{
                  localStorage.setItem(savedTokenKey, token);
                }} else {{
                  localStorage.removeItem(savedTokenKey);
                }}
              }});
            }})();
          </script>
        </body>
        </html>
        """
    )


@admin_router.post("/login")
def login_submit(request: Request, token: str = Form(...), db=Depends(get_db)):
    retry_after = check_rate_limit(
        request,
        scope="admin_login",
        max_requests=AUTH_RATE_LIMIT_ADMIN_LOGIN_MAX_REQUESTS,
        window_seconds=AUTH_RATE_LIMIT_WINDOW_SECONDS,
    )
    if retry_after is not None:
        return RedirectResponse(
            url="/admin/login?error=rate_limited",
            status_code=303,
            headers={"Retry-After": str(retry_after)},
        )

    user = get_or_load_user_by_token(db, token.strip())
    if not user:
        return RedirectResponse(url="/admin/login?error=invalid", status_code=303)
    if parse_iso(user["expires_at"]) < now_utc():
        return RedirectResponse(url="/admin/login?error=expired", status_code=303)
    if not has_permission(user, "manage"):
        return RedirectResponse(url="/admin/login?error=forbidden", status_code=303)
    request.session["user_id"] = user["id"]
    return RedirectResponse(url="/admin", status_code=303)


@admin_router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/admin/login?error=logged_out", status_code=303)


@admin_router.get("")
@admin_router.get("/")
def home(request: Request):
    db = open_db()
    try:
        current_user = get_admin_from_session(request, db)
        if not current_user:
            return RedirectResponse(url="/admin/login", status_code=303)
        users = db.execute(
            "SELECT id, name, expires_at, remark, token, permissions, domains, created_at, updated_at, is_admin FROM users ORDER BY id ASC"
        ).fetchall()
        return HTMLResponse(render_admin_html(users, current_user))
    finally:
        db.close()


@admin_router.post("/users")
async def user_create(request: Request):
    db = open_db()
    try:
        current_user = get_admin_from_session(request, db)
        if not current_user:
            return RedirectResponse(url="/admin/login", status_code=303)
        form = await request.form()
        name = str(form.get("name", "")).strip()
        expires_at = str(form.get("expires_at", "")).strip()
        remark = str(form.get("remark", "")).strip()
        token = str(form.get("token", "")).strip()
        domains = normalize_domains(str(form.get("domains", "")).strip() or "*")
        quick_role = str(form.get("quick_role", "")).strip().lower()
        permissions = QUICK_ROLE_PERMISSIONS.get(quick_role) or normalize_permissions(form.getlist("permissions"))

        if quick_role in QUICK_ROLE_PERMISSIONS:
            name = generate_quick_name()
            expires_at = generate_quick_expires_at()
            remark = ""
            token = generate_quick_token()
            domains = ["*"]

        if not name or not expires_at or not token or not permissions or not domains:
            return PlainTextResponse("name/expires_at/token/permissions/domains 必填", status_code=400)
        try:
            expires_at = normalize_admin_form_expires_at(expires_at)
        except Exception:
            return PlainTextResponse("expires_at 格式错误，请使用日期时间控件", status_code=400)

        ts = now_iso()
        try:
            db.execute(
                """
                INSERT INTO users (name, token, expires_at, remark, permissions, domains, is_admin, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, FALSE, %s, %s)
                """,
                (name, token, expires_at, remark, ",".join(permissions), ",".join(domains), ts, ts),
            )
            db.commit()
            invalidate_tokens([token])
        except psycopg.IntegrityError as exc:
            if not is_unique_violation(exc):
                raise
            return PlainTextResponse("token 已存在", status_code=409)
        return RedirectResponse(url="/admin", status_code=303)
    finally:
        db.close()


@admin_router.post("/users/{user_id}")
async def user_update(user_id: int, request: Request):
    db = open_db()
    try:
        current_user = get_admin_from_session(request, db)
        if not current_user:
            return RedirectResponse(url="/admin/login", status_code=303)
        user = find_user_by_id(db, user_id)
        if not user:
            return PlainTextResponse("用户不存在", status_code=404)

        form = await request.form()
        name = str(form.get("name", "")).strip()
        expires_at = str(form.get("expires_at", "")).strip()
        remark = str(form.get("remark", "")).strip()
        token = str(form.get("token", "")).strip()
        permissions = normalize_permissions(form.getlist("permissions"))
        domains = normalize_domains(str(form.get("domains", "")).strip() or "*")

        if not name or not expires_at or not token or not permissions or not domains:
            return PlainTextResponse("name/expires_at/token/permissions/domains 必填", status_code=400)
        try:
            expires_at = normalize_admin_form_expires_at(expires_at)
        except Exception:
            return PlainTextResponse("expires_at 格式错误，请使用日期时间控件", status_code=400)
        admin_error = validate_admin_update(user, permissions, expires_at)
        if admin_error:
            error_map = {
                "admin user must keep manage permission": "管理员账号必须保留 manage 权限",
                "admin user cannot be expired": "管理员账号不能设置为已过期",
            }
            return PlainTextResponse(error_map.get(admin_error, admin_error), status_code=400)

        try:
            db.execute(
                """
                UPDATE users
                SET name = %s, expires_at = %s, remark = %s, token = %s, permissions = %s, domains = %s, updated_at = %s
                WHERE id = %s
                """,
                (name, expires_at, remark, token, ",".join(permissions), ",".join(domains), now_iso(), user_id),
            )
            db.commit()
            invalidate_tokens([str(user["token"]), token])
        except psycopg.IntegrityError as exc:
            if not is_unique_violation(exc):
                raise
            return PlainTextResponse("token 已存在", status_code=409)
        return RedirectResponse(url="/admin", status_code=303)
    finally:
        db.close()


@admin_router.post("/users/{user_id}/delete")
async def user_delete(user_id: int, request: Request):
    db = open_db()
    try:
        current_user = get_admin_from_session(request, db)
        if not current_user:
            return RedirectResponse(url="/admin/login", status_code=303)
        user = find_user_by_id(db, user_id)
        if not user:
            return PlainTextResponse("用户不存在", status_code=404)
        if bool(user["is_admin"]):
            return PlainTextResponse("管理员账号不可删除", status_code=400)

        db.execute("DELETE FROM users WHERE id = %s", (user_id,))
        db.commit()
        invalidate_tokens([str(user["token"])])
        return RedirectResponse(url="/admin", status_code=303)
    finally:
        db.close()


def render_admin_html(users, current_user):
    rows = []
    for u in users:
        permissions = str(u["permissions"])
        domains = str(u.get("domains") or "*")
        full_token = str(u["token"])
        remark = str(u["remark"] or "")
        rows.append(
            f"""
            <tr>
              <td class="id-col">{u['id']}</td>
              <td class="name-col">{html.escape(str(u['name']))}</td>
              <td class="time-col">{html.escape(format_display_timestamp(str(u['expires_at'])))}</td>
              <td class="remark-col">
                <textarea class=\"remark-input\" name=\"remark\" placeholder=\"备注\" rows=\"3\" form=\"update-form-{u['id']}\">{html.escape(remark)}</textarea>
              </td>
              <td class="token-col">
                <details>
                  <summary>点击显示</summary>
                  <div>{html.escape(full_token)}</div>
                </details>
              </td>
              <td class="time-col">{html.escape(format_display_timestamp(str(u['created_at'])))}</td>
              <td class="time-col">{html.escape(format_display_timestamp(str(u['updated_at'])))}</td>
              <td class="domains-col">
                <textarea class=\"domains-input\" name=\"domains\" placeholder=\"域名,逗号分隔或*\" rows=\"3\" form=\"update-form-{u['id']}\" required>{html.escape(domains)}</textarea>
              </td>
              <td class="ops-col">
                <form id=\"update-form-{u['id']}\" class=\"inline ops-form\" method=\"post\" action=\"/admin/users/{u['id']}\">
                  <input type=\"text\" name=\"name\" value=\"{html.escape(str(u['name']))}\" required>
                  <input type=\"datetime-local\" name=\"expires_at\" value=\"{html.escape(to_datetime_local_value(str(u['expires_at'])))}\" step=\"1\" required>
                  <input class=\"token\" type=\"password\" name=\"token\" value=\"{html.escape(str(u['token']))}\" required>
                  <label><input type=\"checkbox\" name=\"permissions\" value=\"manage\" {'checked' if 'manage' in permissions.split(',') else ''}>管</label>
                  <label><input type=\"checkbox\" name=\"permissions\" value=\"view\" {'checked' if 'view' in permissions.split(',') else ''}>看</label>
                  <label><input type=\"checkbox\" name=\"permissions\" value=\"edit\" {'checked' if 'edit' in permissions.split(',') else ''}>编</label>
                </form>
                <div class="ops-actions">
                  <button type=\"submit\" form=\"update-form-{u['id']}\">更新</button>
                  {
                      "<span>管理员账号不可删除</span>"
                      if u["is_admin"]
                      else f'''
                <form method="post" action="/admin/users/{u['id']}/delete" onsubmit="return confirm('确认删除该账号？');">
                  <button type="submit">删除</button>
                </form>
                '''
                  }
                </div>
              </td>
            </tr>
            """
        )

    return f"""
    <!doctype html>
    <html lang=\"zh\">
    <head>
      <meta charset=\"utf-8\">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      {FAVICON_LINK_HTML}
      <title>鉴权管理后台</title>
      <style>
        body {{ font-family: sans-serif; margin: 24px; }}
        .table-wrap {{
          width: 100%;
          overflow-x: auto;
          --table-min-width: 1310px;
          --id-col-width: 64px;
          --name-col-width: 128px;
          --time-col-width: 184px;
          --remark-col-width: 160px;
          --domains-col-width: 220px;
          --token-col-width: 160px;
          --ops-col-width: 470px;
        }}
        table {{ border-collapse: collapse; width: max(100%, var(--table-min-width)); table-layout: fixed; }}
        table, th, td {{ border: 1px solid #aaa; }}
        th, td {{
          padding: 10px 8px;
          text-align: left;
          white-space: normal;
          word-break: break-word;
          overflow-wrap: anywhere;
          vertical-align: top;
          line-height: 1.5;
          min-width: 0;
        }}
        tr {{ min-height: 72px; }}
        form.inline {{ display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }}
        .create-user-form {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }}
        .create-user-form .actions {{
          display: flex;
          flex-basis: 100%;
          gap: 8px;
          align-items: center;
          flex-wrap: wrap;
        }}
        form.inline input[type=text] {{ width: min(100%, 120px); }}
        form.inline input[type=datetime-local] {{ width: min(100%, 190px); }}
        .token {{ width: min(100%, 170px); }}
        .domains {{ width: 100%; box-sizing: border-box; }}
        .domains-input {{
          width: 100%;
          min-height: 72px;
          box-sizing: border-box;
          resize: vertical;
        }}
        .ops-form {{ margin-bottom: 6px; }}
        .ops-actions {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }}
        .remark-input {{ width: min(100%, 140px); }}
        .remark-col .remark-input {{
          width: 100%;
          min-height: 72px;
          box-sizing: border-box;
          resize: vertical;
        }}
        .ops-col input[type=text] {{ width: min(100%, 104px); }}
        .ops-col input[type=datetime-local] {{ width: min(100%, 160px); }}
        .ops-col .token {{ width: min(100%, 140px); }}
        .id-col {{ width: var(--id-col-width); }}
        .name-col {{ width: var(--name-col-width); }}
        .time-col {{ width: var(--time-col-width); }}
        .remark-col {{ width: var(--remark-col-width); }}
        .domains-col {{ width: var(--domains-col-width); }}
        .token-col {{ width: var(--token-col-width); }}
        .ops-col {{ width: var(--ops-col-width); }}
        .token-col details,
        .token-col summary,
        .token-col div {{ min-width: 0; }}

        @media (max-width: 960px) {{
          body {{ margin: 16px; }}
          th, td {{ padding: 8px 6px; }}
          .table-wrap {{
            --table-min-width: 1200px;
            --id-col-width: 56px;
            --name-col-width: 112px;
            --time-col-width: 168px;
            --remark-col-width: 144px;
            --domains-col-width: 200px;
            --token-col-width: 144px;
            --ops-col-width: 430px;
          }}
          form.inline input[type=text] {{ width: min(100%, 100px); }}
          form.inline input[type=datetime-local] {{ width: min(100%, 170px); }}
          .token {{ width: min(100%, 150px); }}
          .domains {{ width: 100%; }}
          .domains-input {{ width: 100%; }}
          .remark-input {{ width: min(100%, 128px); }}
          .remark-col .remark-input {{ width: 100%; }}
          .ops-col input[type=text] {{ width: min(100%, 92px); }}
          .ops-col input[type=datetime-local] {{ width: min(100%, 148px); }}
          .ops-col .token {{ width: min(100%, 132px); }}
        }}
      </style>
    </head>
    <body>
      <h1>鉴权管理后台</h1>
      <p>当前管理员: {html.escape(str(current_user['name']))} | <a href=\"/admin/logout\">退出</a></p>

      <h2>新增用户</h2>
      <form class="create-user-form" method="post" action="/admin/users">
        <input name="name" type="text" placeholder="名称">
        <input name="expires_at" type="datetime-local" value="{html.escape(to_datetime_local_value(generate_quick_expires_at()))}" step="1" required>
        <input name="remark" class="remark-input" type="text" placeholder="备注">
        <input name="token" class="token" type="text" placeholder="token">
        <input name="domains" class="domains" type="text" value="*" placeholder="域名,逗号分隔或*">
        <label><input type=\"checkbox\" name=\"permissions\" value=\"manage\">管理</label>
        <label><input type=\"checkbox\" name=\"permissions\" value=\"view\">查看</label>
        <label><input type=\"checkbox\" name=\"permissions\" value=\"edit\">编辑</label>
        <span class=\"actions\">
          <button type=\"submit\">自定义创建</button>
          <button type=\"submit\" name=\"quick_role\" value=\"editor\">一键创建编辑者</button>
          <button type=\"submit\" name=\"quick_role\" value=\"viewer\">一键创建查看者</button>
        </span>
      </form>
      <p>时间使用日期时间控件编辑，按服务器本地时区处理。域名使用英文逗号分隔，`*` 表示全部域名。</p>

      <h2>用户列表</h2>
      <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th class="id-col">ID</th><th class="name-col">名称</th><th class="time-col">期限</th><th class="remark-col">备注</th><th class="token-col">Token</th><th class="time-col">创建时间</th><th class="time-col">修改时间</th><th class="domains-col">域名范围</th><th class="ops-col">操作</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
      </div>
      <script>
        (function () {{
          const wrap = document.querySelector(".table-wrap");
          const table = wrap && wrap.querySelector("table");
          if (!wrap || !table) {{
            return;
          }}

          const columns = [
            {{ key: "id", min: 64, weight: 5, count: 1 }},
            {{ key: "name", min: 128, weight: 10, count: 1 }},
            {{ key: "time", min: 184, weight: 13, count: 3 }},
            {{ key: "remark", min: 160, weight: 10, count: 1 }},
            {{ key: "token", min: 160, weight: 10, count: 1 }},
            {{ key: "domains", min: 220, weight: 18, count: 1 }},
            {{ key: "ops", min: 470, weight: 34, count: 1 }},
          ];

          function updateTableWidths() {{
            const available = Math.max(wrap.clientWidth, 320);
            const totalMin = columns.reduce((sum, col) => sum + col.min * col.count, 0);
            const totalWeight = columns.reduce((sum, col) => sum + col.weight * col.count, 0);
            const extra = Math.max(available - totalMin, 0);
            wrap.style.setProperty("--table-min-width", `${{totalMin}}px`);
            for (const col of columns) {{
              const width = col.min + (extra * (col.weight * col.count) / totalWeight / col.count);
              wrap.style.setProperty(`--${{col.key}}-col-width`, `${{width}}px`);
            }}
          }}

          if (typeof ResizeObserver !== "undefined") {{
            new ResizeObserver(updateTableWidths).observe(wrap);
          }} else {{
            window.addEventListener("resize", updateTableWidths);
          }}
          updateTableWidths();
        }})();
      </script>
    </body>
    </html>
    """


def get_admin_from_session(request: Request, db):
    uid = request.session.get("user_id")
    if not uid:
        return None
    user = find_user_by_id(db, uid)
    if not user:
        request.session.clear()
        return None
    if parse_iso(user["expires_at"]) < now_utc():
        request.session.clear()
        return None
    if not has_permission(user, "manage"):
        return None
    return user
