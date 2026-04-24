# 鉴权服务接口文档

基址示例：`http://<host>:8080`

## 认证方式

需要鉴权的接口支持两种传 token 方式：
- `Authorization: Bearer <token>`
- `X-Token: <token>`

权限值：`manage` / `view` / `edit`
- `manage` 视为超级权限（包含 `view`、`edit` 能力）

域名范围：
- 用户返回结构中的 `domains` 表示该 token 可用的域名范围
- `*` 表示全部域名
- `/api/validate` 可选传 `domain` 做域名范围校验

---

## 1) 健康检查

### GET `/healthz`

**响应**
```json
{"ok": true}
```

---

## 2) Token 登录校验

### POST `/api/login`

用于验证 token 并返回用户公开信息。

**请求体**
```json
{
  "token": "your-token"
}
```

**成功响应 200**
```json
{
  "id": 2,
  "name": "alice",
  "expires_at": "2026-03-28T12:00:00+00:00",
  "permissions": ["view", "edit"],
  "domains": ["echo.icehe.life", "stat.icehe.life"],
  "created_at": "2026-03-21T00:00:00+00:00",
  "updated_at": "2026-03-21T00:00:00+00:00"
}
```

**失败响应**
- `400`：`token is required`
- `401`：`invalid token` / `token expired`
- `429`：`too many requests`

---

## 3) Token 有效性/权限校验（推荐给其他项目调用）

### POST `/api/validate`

用于机器间鉴权。

**请求体**
```json
{
  "token": "your-token",
  "permission": "view",
  "domain": "echo.icehe.life"
}
```

字段说明：
- `token`：必填
- `permission`：可选，支持 `manage` / `view` / `edit`
- `domain`：可选，传入后会额外校验该 token 是否拥有该域名范围；`*` 视为全部域名

**成功响应（token 有效且满足 permission）**
```json
{
  "valid": true,
  "id": 2,
  "permissions": ["view", "edit"],
  "domains": ["echo.icehe.life", "stat.icehe.life"]
}
```

**失败响应（统一 200，靠 valid/reason 判断）**
```json
{
  "valid": false,
  "permissions": [],
  "domains": [],
  "reason": "invalid token"
}
```

可能的 `reason`：
- `token is required`
- `invalid token`
- `token expired`
- `invalid permission`
- `forbidden`（token 有效但不具备请求权限）
- `forbidden domain`（token 有效，但域名范围不匹配）

限流命中时接口返回 `429`，并带 `Retry-After` 响应头。
默认 `127.0.0.1` 和 `::1` 在限流白名单内，不参与计数。

> 说明：`manage` 用户请求 `view` / `edit` 时会通过。

---

## 4) 当前用户信息

### GET `/api/me`

需要权限：`view`

**请求头**（二选一）
- `Authorization: Bearer <token>`
- `X-Token: <token>`

**成功响应 200**：同 `/api/login` 返回结构。

**失败响应**
- `401`：`missing token` / `invalid token` / `token expired`
- `403`：`forbidden`

---

## 5) 用户管理接口（管理员）

### GET `/api/users`

需要权限：`manage`

**成功响应 200**
```json
[
  {
    "id": 1,
    "name": "admin",
    "expires_at": "2099-12-31T23:59:59+00:00",
    "permissions": ["manage", "view", "edit"],
    "domains": ["*"],
    "created_at": "...",
    "updated_at": "...",
    "token": "full-token",
    "is_admin": true
  }
]
```

### POST `/api/users`

需要权限：`manage`

**请求体**
```json
{
  "name": "bob",
  "token": "bob-token",
  "expires_at": "2026-03-28T12:00:00+00:00",
  "permissions": ["view", "edit"],
  "domains": ["echo.icehe.life", "stat.icehe.life"]
}
```

**成功响应**：`201` + `{"ok": true}`

**失败响应**
- `400`：字段缺失或 `expires_at` 非 ISO
- `409`：`token already exists`

### PUT `/api/users/{user_id}`

需要权限：`manage`

**请求体**同 POST `/api/users`

**成功响应**：`200` + `{"ok": true}`

**失败响应**
- `404`：`user not found`
- `400`：字段或时间格式错误
- `400`：`admin user must keep manage permission`
- `400`：`admin user cannot be expired`
- `409`：`token already exists`

### DELETE `/api/users/{user_id}`

需要权限：`manage`

仅允许删除非管理员账号。

**成功响应**：`200` + `{"ok": true}`

**失败响应**
- `404`：`user not found`
- `400`：`admin user cannot be deleted`

## 6) 管理后台表单接口

以下接口供服务端渲染的 `/admin` 页面使用，不作为外部 JSON API。

### POST `/admin/users/{user_id}/autosave`

需要已登录管理员 session。

用于用户列表自动保存以下字段：
- `expires_at`
- `remark`
- `domains`
- `permissions`

请求为 `application/x-www-form-urlencoded`，包含 `field` 和当前行的自动保存字段值。后端会保留数据库中已有的 `name` 和 `token`，因此自动保存不会顺带保存未点击 `更新名称和token` 的名称或 token 改动。

**成功响应**：`200` + `ok`

**失败响应**：返回中文纯文本错误，例如 `管理员账号必须保留 manage 权限`、`管理员账号不能设置为已过期`。

---

## 给其他项目 Claude 的调用建议

1. 业务侧优先调用 `POST /api/validate`。
2. 传 `permission` 做权限判断（如 `view` / `edit` / `manage`）。
3. 如果业务是按站点/域名隔离，额外传 `domain`。
4. 以 `valid` 作为准入依据，`reason` 作为错误提示。
5. 不要依赖 HTTP 状态码区分 validate 失败原因（该接口失败也返回 200）。

---

## 给其他项目 Claude 的最小接入模板

### JavaScript / TypeScript (Node 18+)

```ts
type ValidateResult = {
  valid: boolean
  id: number
  permissions: string[]
  domains: string[]
  reason?: string
}

export async function checkAuthByToken(params: {
  authBaseUrl: string
  token: string
  permission?: 'manage' | 'view' | 'edit'
  domain?: string
}): Promise<ValidateResult> {
  const { authBaseUrl, token, permission, domain } = params

  const resp = await fetch(`${authBaseUrl}/api/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, permission, domain }),
  })

  // /api/validate 约定：业务结果看 JSON 的 valid/reason，不依赖 HTTP 状态码
  const data = (await resp.json()) as ValidateResult
  return data
}

// 使用示例
// const result = await checkAuthByToken({
//   authBaseUrl: 'http://127.0.0.1:8080',
//   token: userToken,
//   permission: 'view',
//   domain: 'echo.icehe.life',
// })
// if (!result.valid) throw new Error(result.reason || 'auth failed')
```

### Claude 调用提示词（可直接给其他项目）

```text
请把本项目的 token 鉴权接入为一个独立函数：
- 调用 POST http://127.0.0.1:8080/api/validate
- 入参: { token, permission }
- permission 使用 view/edit/manage 之一
- 不要依赖 HTTP 状态码判断鉴权结果
- 以响应 JSON 的 valid 字段作为准入依据，reason 作为失败原因
- 当 valid=false 时中断当前业务并返回 reason
```

---

## 本地快速示例（curl）

```bash
curl -s -X POST http://127.0.0.1:8080/api/validate \
  -H 'Content-Type: application/json' \
  -d '{"token":"your-token","permission":"view"}'
```

```bash
curl -s http://127.0.0.1:8080/api/me \
  -H 'Authorization: Bearer your-token'
```
