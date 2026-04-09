package main

import (
	"fmt"
	"html"
	"strings"
)

func renderLoginHTML(errorText string) string {
	errorHTML := ""
	if errorText != "" {
		errorHTML = "<p style='color:#b91c1c'>" + html.EscapeString(errorText) + "</p>"
	}
	return fmt.Sprintf(`<!doctype html>
<html lang="zh">
<head><meta charset="utf-8"><link rel="icon" type="image/svg+xml" href="/favicon.svg"><link rel="alternate icon" type="image/x-icon" href="/favicon.ico"><title>鉴权后台登录</title></head>
<body>
  <h1>鉴权后台登录</h1>
  %s
  <form id="login-form" method="post" action="/admin/login">
    <label>Token: <input id="token" type="password" name="token" style="width: 320px;" autocomplete="current-password" autocapitalize="off" autocorrect="off" spellcheck="false" required></label>
    <button type="submit">登录</button>
  </form>
  <script>
    (function () {
      const form = document.getElementById("login-form");
      const tokenInput = document.getElementById("token");
      const savedTokenKey = "auth_admin_token";
      const error = new URLSearchParams(window.location.search).get("error") || "";

      if (error === "invalid" || error === "expired" || error === "forbidden" || error === "logged_out") {
        localStorage.removeItem(savedTokenKey);
      }

      const savedToken = localStorage.getItem(savedTokenKey) || "";
      if (savedToken) {
        tokenInput.value = savedToken;
        if (!error) {
          form.requestSubmit();
        }
      }

      form.addEventListener("submit", function () {
        const token = tokenInput.value.trim();
        if (token) {
          localStorage.setItem(savedTokenKey, token);
        } else {
          localStorage.removeItem(savedTokenKey);
        }
      });
    })();
  </script>
</body>
</html>`, errorHTML)
}

func renderAdminHTML(users []User, currentUser User) string {
	var rows strings.Builder
	for _, user := range users {
		permissions := strings.Split(user.Permissions, ",")
		permissionSet := make(map[string]bool, len(permissions))
		for _, permission := range permissions {
			permissionSet[strings.TrimSpace(permission)] = true
		}
		deleteHTML := "<span>管理员账号不可删除</span>"
		if !user.IsAdmin {
			deleteHTML = fmt.Sprintf(`<form method="post" action="/admin/users/%d/delete" onsubmit="return confirm('确认删除该账号？');">
  <button type="submit">删除</button>
</form>`, user.ID)
		}

		rows.WriteString(fmt.Sprintf(`
            <tr>
              <td class="id-col">%d</td>
              <td class="name-col">%s</td>
              <td class="time-col">%s</td>
              <td class="remark-col">
                <textarea class="remark-input" name="remark" placeholder="备注" rows="3" form="update-form-%d">%s</textarea>
              </td>
              <td class="token-col">
                <details>
                  <summary>点击显示</summary>
                  <div>%s</div>
                </details>
              </td>
              <td class="time-col">%s</td>
              <td class="time-col">%s</td>
              <td class="domains-col">
                <textarea class="domains-input" name="domains" placeholder="域名,逗号分隔或*" rows="3" form="update-form-%d" required>%s</textarea>
              </td>
              <td class="ops-col">
                <form id="update-form-%d" class="inline ops-form" method="post" action="/admin/users/%d">
                  <input type="text" name="name" value="%s" required>
                  <input type="datetime-local" name="expires_at" value="%s" step="1" required>
                  <input class="token" type="password" name="token" value="%s" required>
                  <label><input type="checkbox" name="permissions" value="manage" %s>管</label>
                  <label><input type="checkbox" name="permissions" value="view" %s>看</label>
                  <label><input type="checkbox" name="permissions" value="edit" %s>编</label>
                </form>
                <div class="ops-actions">
                  <button type="submit" form="update-form-%d">更新</button>
                  %s
                </div>
              </td>
            </tr>`,
			user.ID,
			html.EscapeString(user.Name),
			html.EscapeString(formatDisplayTimestamp(user.ExpiresAt)),
			user.ID,
			html.EscapeString(user.Remark),
			html.EscapeString(user.Token),
			html.EscapeString(formatDisplayTimestamp(user.CreatedAt)),
			html.EscapeString(formatDisplayTimestamp(user.UpdatedAt)),
			user.ID,
			html.EscapeString(user.Domains),
			user.ID,
			user.ID,
			html.EscapeString(user.Name),
			html.EscapeString(toDateTimeLocalValue(user.ExpiresAt)),
			html.EscapeString(user.Token),
			checkedAttr(permissionSet["manage"]),
			checkedAttr(permissionSet["view"]),
			checkedAttr(permissionSet["edit"]),
			user.ID,
			deleteHTML,
		))
	}

	return fmt.Sprintf(`<!doctype html>
<html lang="zh">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <link rel="alternate icon" type="image/x-icon" href="/favicon.ico">
  <title>鉴权管理后台</title>
  <style>
    body { font-family: sans-serif; margin: 24px; }
    .table-wrap {
      width: 100%%;
      overflow-x: auto;
      --table-min-width: 1310px;
      --id-col-width: 64px;
      --name-col-width: 128px;
      --time-col-width: 184px;
      --remark-col-width: 160px;
      --domains-col-width: 220px;
      --token-col-width: 160px;
      --ops-col-width: 470px;
    }
    table { border-collapse: collapse; width: max(100%%, var(--table-min-width)); table-layout: fixed; }
    table, th, td { border: 1px solid #aaa; }
    th, td {
      padding: 10px 8px;
      text-align: left;
      white-space: normal;
      word-break: break-word;
      overflow-wrap: anywhere;
      vertical-align: top;
      line-height: 1.5;
      min-width: 0;
    }
    tr { min-height: 72px; }
    form.inline { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
    .create-user-form { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    .create-user-form .actions {
      display: flex;
      flex-basis: 100%%;
      gap: 8px;
      align-items: center;
      flex-wrap: wrap;
    }
    form.inline input[type=text] { width: min(100%%, 120px); }
    form.inline input[type=datetime-local] { width: min(100%%, 190px); }
    .token { width: min(100%%, 170px); }
    .domains { width: 100%%; box-sizing: border-box; }
    .domains-input {
      width: 100%%;
      min-height: 72px;
      box-sizing: border-box;
      resize: vertical;
    }
    .ops-form { margin-bottom: 6px; }
    .ops-actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    .remark-input { width: min(100%%, 140px); }
    .remark-col .remark-input {
      width: 100%%;
      min-height: 72px;
      box-sizing: border-box;
      resize: vertical;
    }
    .ops-col input[type=text] { width: min(100%%, 104px); }
    .ops-col input[type=datetime-local] { width: min(100%%, 160px); }
    .ops-col .token { width: min(100%%, 140px); }
    .id-col { width: var(--id-col-width); }
    .name-col { width: var(--name-col-width); }
    .time-col { width: var(--time-col-width); }
    .remark-col { width: var(--remark-col-width); }
    .domains-col { width: var(--domains-col-width); }
    .token-col { width: var(--token-col-width); }
    .ops-col { width: var(--ops-col-width); }
    .token-col details,
    .token-col summary,
    .token-col div { min-width: 0; }
    @media (max-width: 960px) {
      body { margin: 16px; }
      th, td { padding: 8px 6px; }
      .table-wrap {
        --table-min-width: 1200px;
        --id-col-width: 56px;
        --name-col-width: 112px;
        --time-col-width: 168px;
        --remark-col-width: 144px;
        --domains-col-width: 200px;
        --token-col-width: 144px;
        --ops-col-width: 430px;
      }
      form.inline input[type=text] { width: min(100%%, 100px); }
      form.inline input[type=datetime-local] { width: min(100%%, 170px); }
      .token { width: min(100%%, 150px); }
      .domains { width: 100%%; }
      .domains-input { width: 100%%; }
      .remark-input { width: min(100%%, 128px); }
      .remark-col .remark-input { width: 100%%; }
      .ops-col input[type=text] { width: min(100%%, 92px); }
      .ops-col input[type=datetime-local] { width: min(100%%, 148px); }
      .ops-col .token { width: min(100%%, 132px); }
    }
  </style>
</head>
<body>
  <h1>鉴权管理后台</h1>
  <p>当前管理员: %s | <a href="/admin/logout">退出</a></p>

  <h2>新增用户</h2>
  <form class="create-user-form" method="post" action="/admin/users">
    <input name="name" type="text" placeholder="名称">
    <input name="expires_at" type="datetime-local" value="%s" step="1" required>
    <input name="remark" class="remark-input" type="text" placeholder="备注">
    <input name="token" class="token" type="text" placeholder="token">
    <input name="domains" class="domains" type="text" value="*" placeholder="域名,逗号分隔或*">
    <label><input type="checkbox" name="permissions" value="manage">管理</label>
    <label><input type="checkbox" name="permissions" value="view">查看</label>
    <label><input type="checkbox" name="permissions" value="edit">编辑</label>
    <span class="actions">
      <button type="submit">自定义创建</button>
      <button type="submit" name="quick_role" value="editor">一键创建编辑者</button>
      <button type="submit" name="quick_role" value="viewer">一键创建查看者</button>
    </span>
  </form>
  <p>时间使用日期时间控件编辑，按服务器本地时区处理。域名使用英文逗号分隔，* 表示全部域名。</p>

  <h2>用户列表</h2>
  <div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th class="id-col">ID</th><th class="name-col">名称</th><th class="time-col">期限</th><th class="remark-col">备注</th><th class="token-col">Token</th><th class="time-col">创建时间</th><th class="time-col">修改时间</th><th class="domains-col">域名范围</th><th class="ops-col">操作</th>
      </tr>
    </thead>
    <tbody>
      %s
    </tbody>
  </table>
  </div>
  <script>
    (function () {
      const wrap = document.querySelector(".table-wrap");
      const table = wrap && wrap.querySelector("table");
      if (!wrap || !table) {
        return;
      }
      const columns = [
        { key: "id", min: 64, weight: 5, count: 1 },
        { key: "name", min: 128, weight: 10, count: 1 },
        { key: "time", min: 184, weight: 13, count: 3 },
        { key: "remark", min: 160, weight: 10, count: 1 },
        { key: "token", min: 160, weight: 10, count: 1 },
        { key: "domains", min: 220, weight: 18, count: 1 },
        { key: "ops", min: 470, weight: 34, count: 1 }
      ];
      function updateTableWidths() {
        const available = Math.max(wrap.clientWidth, 320);
        const totalMin = columns.reduce((sum, col) => sum + col.min * col.count, 0);
        const totalWeight = columns.reduce((sum, col) => sum + col.weight * col.count, 0);
        const extra = Math.max(available - totalMin, 0);
        wrap.style.setProperty("--table-min-width", String(totalMin) + "px");
        for (const col of columns) {
          const width = col.min + (extra * (col.weight * col.count) / totalWeight / col.count);
          wrap.style.setProperty("--" + col.key + "-col-width", String(width) + "px");
        }
      }
      if (typeof ResizeObserver !== "undefined") {
        new ResizeObserver(updateTableWidths).observe(wrap);
      } else {
        window.addEventListener("resize", updateTableWidths);
      }
      updateTableWidths();
    })();
  </script>
</body>
</html>`, html.EscapeString(currentUser.Name), html.EscapeString(toDateTimeLocalValue(generateQuickExpiresAt())), rows.String())
}

func checkedAttr(checked bool) string {
	if checked {
		return "checked"
	}
	return ""
}
