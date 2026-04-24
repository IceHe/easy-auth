package main

import (
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) handleAdminLoginPage(w http.ResponseWriter, r *http.Request) {
	errorCode := strings.TrimSpace(r.URL.Query().Get("error"))
	errorMap := map[string]string{
		"invalid":      "token 无效",
		"expired":      "token 已过期",
		"forbidden":    "仅管理员可登录后台",
		"logged_out":   "已退出登录",
		"rate_limited": "请求过多，请稍后再试",
	}
	errorText := errorMap[errorCode]
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(renderLoginHTML(errorText)))
}

func (s *Server) handleAdminLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if retryAfter := s.rateLimiter.Check(r, "admin_login", s.cfg.AdminLoginMaxRequests, s.cfg.RateLimitWindow); retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		http.Redirect(w, r, "/admin/login?error=rate_limited", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/login?error=invalid", http.StatusSeeOther)
		return
	}

	token := strings.TrimSpace(r.FormValue("token"))
	user, err := s.getUserByToken(r.Context(), token)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if user == nil {
		http.Redirect(w, r, "/admin/login?error=invalid", http.StatusSeeOther)
		return
	}
	if expired(*user) {
		http.Redirect(w, r, "/admin/login?error=expired", http.StatusSeeOther)
		return
	}
	if !hasPermission(*user, "manage") {
		http.Redirect(w, r, "/admin/login?error=forbidden", http.StatusSeeOther)
		return
	}

	s.setSessionCookie(w, user.ID)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/admin/login?error=logged_out", http.StatusSeeOther)
}

func (s *Server) handleAdminHome(w http.ResponseWriter, r *http.Request) {
	currentUser, ok, err := s.adminFromSession(r)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if !ok {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	users, err := s.listUsers(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(renderAdminHTML(users, *currentUser)))
}

func (s *Server) handleAdminUsersCreate(w http.ResponseWriter, r *http.Request) {
	_, ok, err := s.adminFromSession(r)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if !ok {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		writePlainText(w, http.StatusBadRequest, "参数错误")
		return
	}

	payload := UserPayload{
		Name:      strings.TrimSpace(r.FormValue("name")),
		Token:     strings.TrimSpace(r.FormValue("token")),
		ExpiresAt: strings.TrimSpace(r.FormValue("expires_at")),
		Remark:    strings.TrimSpace(r.FormValue("remark")),
		Domains:   splitCSV(r.FormValue("domains")),
	}
	quickRole := strings.ToLower(strings.TrimSpace(r.FormValue("quick_role")))
	if quickRole == "viewer" || quickRole == "editor" {
		payload.Name = generateQuickName()
		payload.ExpiresAt = generateQuickExpiresAt()
		payload.Remark = ""
		payload.Token = randomHex(32)
		payload.Permissions = map[string][]string{
			"viewer": {"view"},
			"editor": {"view", "edit"},
		}[quickRole]
		payload.Domains = []string{"*"}
	} else {
		payload.Permissions = r.Form["permissions"]
	}

	normalized, message := normalizeAdminFormPayload(payload)
	if message != "" {
		writePlainText(w, http.StatusBadRequest, message)
		return
	}
	if err := s.insertUser(r.Context(), normalized, false); err != nil {
		if isUniqueViolation(err) {
			writePlainText(w, http.StatusConflict, "token 已存在")
			return
		}
		s.internalError(w, err)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAdminUsersUpdate(w http.ResponseWriter, r *http.Request) {
	_, ok, err := s.adminFromSession(r)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if !ok {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	userID, parsed := parsePathID(r.PathValue("userID"))
	if !parsed {
		http.NotFound(w, r)
		return
	}

	user, err := s.findUserByID(r.Context(), userID)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if user == nil {
		writePlainText(w, http.StatusNotFound, "用户不存在")
		return
	}

	if err := r.ParseForm(); err != nil {
		writePlainText(w, http.StatusBadRequest, "参数错误")
		return
	}

	payload := UserPayload{
		Name:        strings.TrimSpace(r.FormValue("name")),
		Token:       strings.TrimSpace(r.FormValue("token")),
		ExpiresAt:   strings.TrimSpace(r.FormValue("expires_at")),
		Remark:      strings.TrimSpace(r.FormValue("remark")),
		Permissions: r.Form["permissions"],
		Domains:     splitCSV(r.FormValue("domains")),
	}
	normalized, message := normalizeAdminFormPayload(payload)
	if message != "" {
		writePlainText(w, http.StatusBadRequest, message)
		return
	}

	if adminMessage := validateAdminUpdate(*user, normalized.Permissions, normalized.ExpiresAt); adminMessage != "" {
		switch adminMessage {
		case "admin user must keep manage permission":
			writePlainText(w, http.StatusBadRequest, "管理员账号必须保留 manage 权限")
		case "admin user cannot be expired":
			writePlainText(w, http.StatusBadRequest, "管理员账号不能设置为已过期")
		default:
			writePlainText(w, http.StatusBadRequest, adminMessage)
		}
		return
	}

	if err := s.updateUser(r.Context(), userID, normalized, *user); err != nil {
		if isUniqueViolation(err) {
			writePlainText(w, http.StatusConflict, "token 已存在")
			return
		}
		s.internalError(w, err)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleAdminUsersAutosave(w http.ResponseWriter, r *http.Request) {
	_, ok, err := s.adminFromSession(r)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if !ok {
		writePlainText(w, http.StatusUnauthorized, "请先登录")
		return
	}

	userID, parsed := parsePathID(r.PathValue("userID"))
	if !parsed {
		http.NotFound(w, r)
		return
	}

	user, err := s.findUserByID(r.Context(), userID)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if user == nil {
		writePlainText(w, http.StatusNotFound, "用户不存在")
		return
	}

	if err := r.ParseForm(); err != nil {
		writePlainText(w, http.StatusBadRequest, "参数错误")
		return
	}

	switch strings.TrimSpace(r.FormValue("field")) {
	case "expires_at", "remark", "domains", "permissions":
	default:
		writePlainText(w, http.StatusBadRequest, "自动更新字段不支持")
		return
	}

	payload := UserPayload{
		Name:        user.Name,
		Token:       user.Token,
		ExpiresAt:   strings.TrimSpace(r.FormValue("expires_at")),
		Remark:      strings.TrimSpace(r.FormValue("remark")),
		Permissions: r.Form["permissions"],
		Domains:     splitCSV(r.FormValue("domains")),
	}
	normalized, message := normalizeAdminFormPayload(payload)
	if message != "" {
		writePlainText(w, http.StatusBadRequest, message)
		return
	}

	if adminMessage := validateAdminUpdate(*user, normalized.Permissions, normalized.ExpiresAt); adminMessage != "" {
		switch adminMessage {
		case "admin user must keep manage permission":
			writePlainText(w, http.StatusBadRequest, "管理员账号必须保留 manage 权限")
		case "admin user cannot be expired":
			writePlainText(w, http.StatusBadRequest, "管理员账号不能设置为已过期")
		default:
			writePlainText(w, http.StatusBadRequest, adminMessage)
		}
		return
	}

	if err := s.updateUser(r.Context(), userID, normalized, *user); err != nil {
		if isUniqueViolation(err) {
			writePlainText(w, http.StatusConflict, "token 已存在")
			return
		}
		s.internalError(w, err)
		return
	}
	writePlainText(w, http.StatusOK, "ok")
}

func (s *Server) handleAdminUsersDelete(w http.ResponseWriter, r *http.Request) {
	_, ok, err := s.adminFromSession(r)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if !ok {
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
		return
	}

	userID, parsed := parsePathID(r.PathValue("userID"))
	if !parsed {
		http.NotFound(w, r)
		return
	}

	user, err := s.findUserByID(r.Context(), userID)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if user == nil {
		writePlainText(w, http.StatusNotFound, "用户不存在")
		return
	}
	if user.IsAdmin {
		writePlainText(w, http.StatusBadRequest, "管理员账号不可删除")
		return
	}

	if _, err := s.db.ExecContext(r.Context(), `DELETE FROM users WHERE id = $1`, userID); err != nil {
		s.internalError(w, err)
		return
	}
	s.tokenCache.Invalidate(user.Token)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
