# 简单通用鉴权服务（Go）

支持能力：
- 通过 token 文本登录（API）
- 初始化一个管理员用户
- 管理员登录后台后新增/更新用户
- 用户字段：名称、期限、token、权限（管理/查看/编辑）、域名范围、创建时间、修改时间

## 1. 安装与启动

```bash
cp .env.example .env
./scripts/build.sh
./bin/wuwa-auth
```

默认监听：`http://127.0.0.1:8080`

## 2. 初始化管理员

首次启动会自动初始化管理员（仅在数据库中不存在管理员时执行）。
运行配置优先从仓库根目录的 `.env` 读取，真实数据库连接串不要写进代码文件。

可配置项：

- `AUTH_ADMIN_NAME`：管理员名称，默认 `admin`
- `AUTH_ADMIN_TOKEN`：管理员 token，默认 `change-me-admin-token`
- `AUTH_ADMIN_EXPIRES_AT`：管理员到期时间（ISO），默认 `2099-12-31T23:59:59+00:00`
- `AUTH_SECRET_KEY`：Session 密钥，默认 `change-me-session-secret`，生产环境务必覆盖
- `AUTH_DB_URL`：PostgreSQL 连接串，必填
- `AUTH_RATE_LIMIT_ENABLED`：是否启用 IP 限流，默认 `true`
- `AUTH_RATE_LIMIT_TRUST_PROXY`：是否信任 `X-Forwarded-For` 作为客户端 IP，默认 `false`
- `AUTH_RATE_LIMIT_IP_WHITELIST`：不参与限流的 IP/CIDR 列表，逗号分隔，默认 `127.0.0.1,::1`
- `AUTH_RATE_LIMIT_WINDOW_SECONDS`：限流窗口秒数，默认 `60`
- `AUTH_RATE_LIMIT_API_LOGIN_MAX_REQUESTS`：`/api/login` 每 IP 每窗口最大请求数，默认 `20`
- `AUTH_RATE_LIMIT_API_VALIDATE_MAX_REQUESTS`：`/api/validate` 每 IP 每窗口最大请求数，默认 `60`
- `AUTH_RATE_LIMIT_ADMIN_LOGIN_MAX_REQUESTS`：`/admin/login` 每 IP 每窗口最大请求数，默认 `10`

`.env` 示例：

```dotenv
AUTH_DB_URL=postgresql://user:password@localhost:5432/dbname
AUTH_ADMIN_NAME=superadmin
AUTH_ADMIN_TOKEN=your-admin-token
AUTH_SECRET_KEY=replace-with-random
```

启动前请先确保 PostgreSQL 数据库已创建且连接串可用。服务会自动建表并初始化首个管理员账号。

默认会将 `127.0.0.1` 和 `::1` 视为限流白名单，避免本机服务调用误触发限流。

部署到 systemd：

```bash
./scripts/build.sh
install -m 644 deploy/wuwa-auth.service /etc/systemd/system/wuwa-auth.service
systemctl daemon-reload
systemctl restart wuwa-auth.service
```

## 3. 登录与鉴权

### API 登录（token 文本）

`POST /api/login`

```json
{
  "token": "your-token"
}
```

### 带 token 访问

支持两种方式：
- `Authorization: Bearer <token>`
- `X-Token: <token>`

## 4. 管理后台

- 登录页：`GET /admin/login`
- 管理页：`GET /admin`
- 退出：`GET /admin/logout`

管理员通过 token 登录后可新增/更新用户，也可删除非管理员账号。

## 5. 用户字段

用户表字段：
- `name` 名称
- `expires_at` 期限（ISO 时间）
- `token` 登录 token（唯一）
- `permissions` 权限（`manage`, `view`, `edit`）
- `domains` 域名范围（如 `echo.icehe.life,stat.icehe.life`，`*` 表示全部域名）
- `created_at` 创建时间
- `updated_at` 修改时间

权限规则：
- 拥有 `manage` 可进行后台管理和用户管理 API
- `view` 用于只读接口
- `edit` 预留给业务修改接口

域名规则：
- `domains` 使用英文逗号分隔多个域名
- `*` 表示拥有所有域名下的权限
- `POST /api/validate` 可额外传 `domain` 做域名范围校验
