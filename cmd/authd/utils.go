package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func normalizeUserPayload(payload UserPayload) (normalizedUserPayload, string) {
	name := strings.TrimSpace(payload.Name)
	token := strings.TrimSpace(payload.Token)
	expiresAt := strings.TrimSpace(payload.ExpiresAt)
	remark := strings.TrimSpace(payload.Remark)
	permissions := normalizePermissions(payload.Permissions)
	domains := normalizeDomains(payload.Domains)

	if name == "" || token == "" || expiresAt == "" || len(permissions) == 0 || len(domains) == 0 {
		return normalizedUserPayload{}, "name/token/expires_at/permissions/domains are required"
	}
	if _, err := parseISO(expiresAt); err != nil {
		return normalizedUserPayload{}, "expires_at must be valid ISO datetime"
	}

	return normalizedUserPayload{
		Name:        name,
		Token:       token,
		ExpiresAt:   expiresAt,
		Remark:      remark,
		Permissions: permissions,
		Domains:     domains,
	}, ""
}

func normalizeAdminFormPayload(payload UserPayload) (normalizedUserPayload, string) {
	name := strings.TrimSpace(payload.Name)
	token := strings.TrimSpace(payload.Token)
	expiresAt := strings.TrimSpace(payload.ExpiresAt)
	remark := strings.TrimSpace(payload.Remark)
	permissions := normalizePermissions(payload.Permissions)
	domains := normalizeDomains(payload.Domains)

	if name == "" || token == "" || expiresAt == "" || len(permissions) == 0 || len(domains) == 0 {
		return normalizedUserPayload{}, "name/expires_at/token/permissions/domains 必填"
	}
	normalizedExpiresAt, err := normalizeAdminFormExpiresAt(expiresAt)
	if err != nil {
		return normalizedUserPayload{}, "expires_at 格式错误，请使用日期时间控件"
	}

	return normalizedUserPayload{
		Name:        name,
		Token:       token,
		ExpiresAt:   normalizedExpiresAt,
		Remark:      remark,
		Permissions: permissions,
		Domains:     domains,
	}, ""
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeDetailError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"detail": detail})
}

func writePlainText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func decodeJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	return decoder.Decode(target)
}

func parsePathID(raw string) (int64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func parseISO(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	layouts := []struct {
		layout   string
		location *time.Location
	}{
		{time.RFC3339Nano, time.UTC},
		{"2006-01-02T15:04:05", time.UTC},
		{"2006-01-02T15:04", time.UTC},
	}

	for _, item := range layouts {
		var parsed time.Time
		var err error
		if item.layout == time.RFC3339Nano {
			parsed, err = time.Parse(item.layout, raw)
		} else {
			parsed, err = time.ParseInLocation(item.layout, raw, item.location)
		}
		if err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid ISO datetime: %q", raw)
}

func expired(user User) bool {
	expiresAt, err := parseISO(user.ExpiresAt)
	if err != nil {
		return true
	}
	return expiresAt.Before(time.Now().UTC())
}

func isValidPermission(value string) bool {
	switch value {
	case "manage", "view", "edit":
		return true
	default:
		return false
	}
}

func normalizePermissions(raw any) []string {
	allowed := map[string]struct{}{
		"manage": {},
		"view":   {},
		"edit":   {},
	}
	values := splitRawValues(raw)
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if _, ok := allowed[value]; !ok {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func splitRawValues(raw any) []string {
	switch value := raw.(type) {
	case string:
		return strings.Split(value, ",")
	case []string:
		return value
	default:
		return nil
	}
}

func normalizeDomains(raw any) []string {
	values := splitRawValues(raw)
	seen := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizeDomainItem(value)
		if normalized == "" {
			continue
		}
		if normalized == "*" {
			return []string{"*"}
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func normalizeDomainItem(value string) string {
	item := strings.ToLower(strings.TrimSpace(value))
	if item == "" {
		return ""
	}
	if item == "*" {
		return "*"
	}
	if strings.Contains(item, "://") {
		parsed, err := url.Parse(item)
		if err == nil {
			if strings.TrimSpace(parsed.Host) != "" {
				item = strings.ToLower(strings.TrimSpace(parsed.Host))
			} else {
				item = strings.ToLower(strings.TrimSpace(parsed.Path))
			}
		}
	}
	if before, _, found := strings.Cut(item, "/"); found {
		item = strings.TrimSpace(before)
	}
	return item
}

func hasPermission(user User, permission string) bool {
	perms := normalizePermissions(user.Permissions)
	for _, item := range perms {
		if item == "manage" || item == permission {
			return true
		}
	}
	return false
}

func hasDomainAccess(user User, domain string) bool {
	domains := normalizeDomains(user.Domains)
	normalized := normalizeDomainItem(domain)
	if normalized == "" {
		return false
	}
	for _, item := range domains {
		if item == "*" || item == normalized {
			return true
		}
	}
	return false
}

func validateAdminUpdate(user User, permissions []string, expiresAt string) string {
	if !user.IsAdmin {
		return ""
	}
	hasManage := false
	for _, permission := range permissions {
		if permission == "manage" {
			hasManage = true
			break
		}
	}
	if !hasManage {
		return "admin user must keep manage permission"
	}
	parsed, err := parseISO(expiresAt)
	if err != nil {
		return "admin user cannot be expired"
	}
	if parsed.Before(time.Now().UTC()) {
		return "admin user cannot be expired"
	}
	return ""
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

func generateQuickName() string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	var buf [6]byte
	randomBytes := make([]byte, len(buf))
	if _, err := rand.Read(randomBytes); err != nil {
		return "user" + time.Now().UTC().Format("20060102150405")
	}
	for index := range buf {
		buf[index] = letters[int(randomBytes[index])%len(letters)]
	}
	return string(buf[:]) + time.Now().UTC().Format("20060102150405")
}

func generateQuickExpiresAt() string {
	return time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339Nano)
}

func normalizeAdminFormExpiresAt(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasSuffix(raw, "Z") || hasExplicitUTCOffset(raw) {
		if parsed, err := parseISO(raw); err == nil {
			return parsed.UTC().Format(time.RFC3339Nano), nil
		}
	}

	location := time.Now().Location()
	layouts := []string{
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
	}
	for _, layout := range layouts {
		parsed, err := time.ParseInLocation(layout, raw, location)
		if err == nil {
			return parsed.UTC().Format(time.RFC3339Nano), nil
		}
	}
	return "", errors.New("invalid datetime-local")
}

func hasExplicitUTCOffset(raw string) bool {
	if len(raw) < len("2006-01-02T15:04:05+08:00") {
		return false
	}
	offset := raw[len(raw)-6:]
	if (offset[0] != '+' && offset[0] != '-') || offset[3] != ':' {
		return false
	}
	for _, index := range []int{1, 2, 4, 5} {
		if offset[index] < '0' || offset[index] > '9' {
			return false
		}
	}
	return true
}

func toDateTimeLocalValue(raw string) string {
	parsed, err := parseISO(raw)
	if err != nil {
		return ""
	}
	return parsed.In(time.Now().Location()).Format("2006-01-02T15:04:05")
}

func formatDisplayTimestamp(raw string) string {
	parsed, err := parseISO(raw)
	if err != nil {
		return raw
	}
	return parsed.In(time.Now().Location()).Format("2006-01-02 15:04:05-07:00")
}

func internalError(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	writeDetailError(w, http.StatusInternalServerError, "internal server error")
}

func (s *Server) internalError(w http.ResponseWriter, err error) {
	internalError(w, err)
}
