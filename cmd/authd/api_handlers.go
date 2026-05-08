package main

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

func (s *Server) handleAPILogin(w http.ResponseWriter, r *http.Request) {
	if retryAfter := s.rateLimiter.Check(r, "api_login", s.cfg.APILoginMaxRequests, s.cfg.RateLimitWindow); retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeDetailError(w, http.StatusTooManyRequests, "too many requests")
		return
	}

	var payload LoginRequest
	if err := decodeJSON(r, &payload); err != nil {
		writeDetailError(w, http.StatusBadRequest, "invalid json")
		return
	}

	token := strings.TrimSpace(payload.Token)
	if token == "" {
		writeDetailError(w, http.StatusBadRequest, "token is required")
		return
	}

	user, err := s.getUserByToken(r.Context(), token)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if user == nil {
		writeDetailError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	if expired(*user) {
		writeDetailError(w, http.StatusUnauthorized, "token expired")
		return
	}

	writeJSON(w, http.StatusOK, user.Public())
}

func (s *Server) handleAPIValidate(w http.ResponseWriter, r *http.Request) {
	if retryAfter := s.rateLimiter.Check(r, "api_validate", s.cfg.APIValidateMaxRequests, s.cfg.RateLimitWindow); retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeDetailError(w, http.StatusTooManyRequests, "too many requests")
		return
	}

	var payload ValidateRequest
	if err := decodeJSON(r, &payload); err != nil {
		writeDetailError(w, http.StatusBadRequest, "invalid json")
		return
	}

	token := strings.TrimSpace(payload.Token)
	permission := strings.ToLower(strings.TrimSpace(payload.Permission))
	domain := strings.TrimSpace(payload.Domain)
	if token == "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":       false,
			"permissions": []string{},
			"domains":     []string{},
			"reason":      "token is required",
		})
		return
	}

	user, err := s.getUserByToken(r.Context(), token)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if user == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":       false,
			"permissions": []string{},
			"domains":     []string{},
			"reason":      "invalid token",
		})
		return
	}

	permissions := normalizePermissions(user.Permissions)
	domains := normalizeDomains(user.Domains)
	if expired(*user) {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":       false,
			"permissions": permissions,
			"domains":     domains,
			"reason":      "token expired",
		})
		return
	}
	if permission != "" && !isValidPermission(permission) {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":       false,
			"permissions": permissions,
			"domains":     domains,
			"reason":      "invalid permission",
		})
		return
	}
	if permission != "" && !hasPermission(*user, permission) {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":       false,
			"permissions": permissions,
			"domains":     domains,
			"reason":      "forbidden",
		})
		return
	}
	if domain != "" && !hasDomainAccess(*user, domain) {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":       false,
			"permissions": permissions,
			"domains":     domains,
			"reason":      "forbidden domain",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"valid":       true,
		"id":          user.ID,
		"permissions": permissions,
		"domains":     domains,
	})
}

func (s *Server) handleAPIMe(w http.ResponseWriter, r *http.Request) {
	user, code, detail, err := s.currentUser(r, "view")
	if err != nil {
		s.internalError(w, err)
		return
	}
	if code != 0 {
		writeDetailError(w, code, detail)
		return
	}
	writeJSON(w, http.StatusOK, user.Public())
}

func (s *Server) handleAPIUsersList(w http.ResponseWriter, r *http.Request) {
	_, code, detail, err := s.currentUser(r, "manage")
	if err != nil {
		s.internalError(w, err)
		return
	}
	if code != 0 {
		writeDetailError(w, code, detail)
		return
	}
	users, err := s.listUsers(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	response := make([]FullUser, 0, len(users))
	for _, user := range users {
		response = append(response, user.Full())
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleAPIUsersCreate(w http.ResponseWriter, r *http.Request) {
	_, code, detail, err := s.currentUser(r, "manage")
	if err != nil {
		s.internalError(w, err)
		return
	}
	if code != 0 {
		writeDetailError(w, code, detail)
		return
	}

	var payload UserPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeDetailError(w, http.StatusBadRequest, "invalid json")
		return
	}

	normalized, message := normalizeUserPayload(payload)
	if message != "" {
		writeDetailError(w, http.StatusBadRequest, message)
		return
	}

	if err := s.insertUser(r.Context(), normalized, false); err != nil {
		if isUniqueViolation(err) {
			writeDetailError(w, http.StatusConflict, "token already exists")
			return
		}
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]bool{"ok": true})
}

func (s *Server) handleAPIUsersUpdate(w http.ResponseWriter, r *http.Request) {
	_, code, detail, err := s.currentUser(r, "manage")
	if err != nil {
		s.internalError(w, err)
		return
	}
	if code != 0 {
		writeDetailError(w, code, detail)
		return
	}

	userID, ok := parsePathID(r.PathValue("userID"))
	if !ok {
		http.NotFound(w, r)
		return
	}

	user, err := s.findUserByID(r.Context(), userID)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if user == nil {
		writeDetailError(w, http.StatusNotFound, "user not found")
		return
	}

	var payload UserPayload
	if err := decodeJSON(r, &payload); err != nil {
		writeDetailError(w, http.StatusBadRequest, "invalid json")
		return
	}

	normalized, message := normalizeUserPayload(payload)
	if message != "" {
		writeDetailError(w, http.StatusBadRequest, message)
		return
	}

	if adminMessage := validateAdminUpdate(*user, normalized.Permissions, normalized.ExpiresAt); adminMessage != "" {
		writeDetailError(w, http.StatusBadRequest, adminMessage)
		return
	}

	if err := s.updateUser(r.Context(), userID, normalized, *user); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeDetailError(w, http.StatusNotFound, "user not found")
			return
		}
		if isUniqueViolation(err) {
			writeDetailError(w, http.StatusConflict, "token already exists")
			return
		}
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAPIUsersDelete(w http.ResponseWriter, r *http.Request) {
	_, code, detail, err := s.currentUser(r, "manage")
	if err != nil {
		s.internalError(w, err)
		return
	}
	if code != 0 {
		writeDetailError(w, code, detail)
		return
	}

	userID, ok := parsePathID(r.PathValue("userID"))
	if !ok {
		http.NotFound(w, r)
		return
	}

	user, err := s.findUserByID(r.Context(), userID)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if user == nil {
		writeDetailError(w, http.StatusNotFound, "user not found")
		return
	}
	if user.IsAdmin {
		writeDetailError(w, http.StatusBadRequest, "admin user cannot be deleted")
		return
	}

	if err := s.softDeleteUser(r.Context(), *user); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeDetailError(w, http.StatusNotFound, "user not found")
			return
		}
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
