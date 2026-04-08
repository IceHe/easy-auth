package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	sessionCookieName = "auth_session"
	sessionTTL        = 7 * 24 * time.Hour
)

//go:embed assets/*
var embeddedAssets embed.FS

type Config struct {
	DatabaseURL string

	AdminName      string
	AdminToken     string
	AdminExpiresAt string
	SecretKey      string

	Port string

	TokenCacheEnabled      bool
	TokenCacheTTL          time.Duration
	TokenCacheMaxSize      int
	RateLimitEnabled       bool
	RateLimitTrustProxy    bool
	RateLimitIPWhitelist   []string
	RateLimitWindow        time.Duration
	APILoginMaxRequests    int
	APIValidateMaxRequests int
	AdminLoginMaxRequests  int
}

type User struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	ExpiresAt   string `json:"expires_at"`
	Remark      string `json:"remark"`
	Token       string `json:"token,omitempty"`
	Permissions string `json:"-"`
	Domains     string `json:"-"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	IsAdmin     bool   `json:"is_admin,omitempty"`
}

type PublicUser struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	ExpiresAt   string   `json:"expires_at"`
	Remark      string   `json:"remark"`
	Permissions []string `json:"permissions"`
	Domains     []string `json:"domains"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

type FullUser struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	ExpiresAt   string   `json:"expires_at"`
	Remark      string   `json:"remark"`
	Token       string   `json:"token"`
	Permissions []string `json:"permissions"`
	Domains     []string `json:"domains"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
	IsAdmin     bool     `json:"is_admin"`
}

type LoginRequest struct {
	Token string `json:"token"`
}

type ValidateRequest struct {
	Token      string `json:"token"`
	Permission string `json:"permission"`
	Domain     string `json:"domain"`
}

type UserPayload struct {
	Name        string   `json:"name"`
	Token       string   `json:"token"`
	ExpiresAt   string   `json:"expires_at"`
	Remark      string   `json:"remark"`
	Permissions []string `json:"permissions"`
	Domains     []string `json:"domains"`
}

type TokenCache struct {
	enabled bool
	ttl     time.Duration
	maxSize int

	mu    sync.Mutex
	items map[string]tokenCacheEntry
}

type tokenCacheEntry struct {
	User     User
	CachedAt time.Time
}

type RateLimiter struct {
	enabled       bool
	trustProxy    bool
	whitelistIPs  []net.IP
	whitelistNets []*net.IPNet

	mu           sync.Mutex
	hits         map[string][]time.Time
	requestCount int
}

type Server struct {
	cfg         Config
	db          *sql.DB
	tokenCache  *TokenCache
	rateLimiter *RateLimiter
	assets      fs.FS
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	database, err := openDB(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer database.Close()

	whitelistIPs, whitelistNets, err := parseIPWhitelist(cfg.RateLimitIPWhitelist)
	if err != nil {
		log.Fatalf("parse rate limit whitelist: %v", err)
	}

	server := &Server{
		cfg:        cfg,
		db:         database,
		tokenCache: NewTokenCache(cfg.TokenCacheEnabled, cfg.TokenCacheTTL, cfg.TokenCacheMaxSize),
		rateLimiter: &RateLimiter{
			enabled:       cfg.RateLimitEnabled,
			trustProxy:    cfg.RateLimitTrustProxy,
			whitelistIPs:  whitelistIPs,
			whitelistNets: whitelistNets,
			hits:          make(map[string][]time.Time),
		},
		assets: mustAssets(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.bootstrap(ctx); err != nil {
		log.Fatalf("bootstrap: %v", err)
	}

	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           server.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("listening on :%s", cfg.Port)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

func mustAssets() fs.FS {
	if embedded, err := fs.Sub(embeddedAssets, "assets"); err == nil {
		return embedded
	}
	return os.DirFS(".")
}

func loadConfig() (Config, error) {
	loadDotenv(".env")

	cfg := Config{
		DatabaseURL:            firstNonEmpty(os.Getenv("AUTH_DB_URL"), os.Getenv("DATABASE_URL")),
		AdminName:              envOr("AUTH_ADMIN_NAME", "admin"),
		AdminToken:             envOr("AUTH_ADMIN_TOKEN", "change-me-admin-token"),
		AdminExpiresAt:         envOr("AUTH_ADMIN_EXPIRES_AT", "2099-12-31T23:59:59+00:00"),
		SecretKey:              envOr("AUTH_SECRET_KEY", ""),
		Port:                   envOr("PORT", "8080"),
		TokenCacheEnabled:      envBool("AUTH_TOKEN_CACHE_ENABLED", true),
		TokenCacheTTL:          time.Duration(envInt("AUTH_TOKEN_CACHE_TTL_SECONDS", 10)) * time.Second,
		TokenCacheMaxSize:      envInt("AUTH_TOKEN_CACHE_MAX_SIZE", 2000),
		RateLimitEnabled:       envBool("AUTH_RATE_LIMIT_ENABLED", true),
		RateLimitTrustProxy:    envBool("AUTH_RATE_LIMIT_TRUST_PROXY", false),
		RateLimitIPWhitelist:   envCSV("AUTH_RATE_LIMIT_IP_WHITELIST", []string{"127.0.0.1", "::1"}),
		RateLimitWindow:        time.Duration(envInt("AUTH_RATE_LIMIT_WINDOW_SECONDS", 60)) * time.Second,
		APILoginMaxRequests:    envInt("AUTH_RATE_LIMIT_API_LOGIN_MAX_REQUESTS", 20),
		APIValidateMaxRequests: envInt("AUTH_RATE_LIMIT_API_VALIDATE_MAX_REQUESTS", 60),
		AdminLoginMaxRequests:  envInt("AUTH_RATE_LIMIT_ADMIN_LOGIN_MAX_REQUESTS", 10),
	}

	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("AUTH_DB_URL or DATABASE_URL is required; configure it in .env or the environment")
	}
	if cfg.SecretKey == "" {
		cfg.SecretKey = randomHex(32)
	}
	return cfg, nil
}

func loadDotenv(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			continue
		}
		if len(value) >= 2 && value[0] == value[len(value)-1] && (value[0] == '"' || value[0] == '\'') {
			value = value[1 : len(value)-1]
		}
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, value)
		}
	}
}

func envOr(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func envBool(name string, fallback bool) bool {
	value, exists := os.LookupEnv(name)
	if !exists {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func envCSV(name string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return append([]string(nil), fallback...)
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return append([]string(nil), fallback...)
	}
	return result
}

func parseIPWhitelist(values []string) ([]net.IP, []*net.IPNet, error) {
	ips := make([]net.IP, 0, len(values))
	nets := make([]*net.IPNet, 0, len(values))
	for _, raw := range values {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid AUTH_RATE_LIMIT_IP_WHITELIST entry %q: %w", entry, err)
			}
			nets = append(nets, network)
			continue
		}
		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid AUTH_RATE_LIMIT_IP_WHITELIST entry %q", entry)
		}
		ips = append(ips, ip)
	}
	return ips, nets, nil
}

func envInt(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func randomHex(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "change-me-session-secret"
	}
	return hex.EncodeToString(buf)
}

func openDB(databaseURL string) (*sql.DB, error) {
	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}
	database.SetConnMaxLifetime(30 * time.Minute)
	database.SetMaxOpenConns(10)
	database.SetMaxIdleConns(5)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, err
	}
	return database, nil
}

func (s *Server) bootstrap(ctx context.Context) error {
	if err := s.ensureSchema(ctx); err != nil {
		return err
	}
	return s.ensureAdminUser(ctx)
}

func (s *Server) ensureSchema(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id BIGSERIAL PRIMARY KEY,
			name TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			expires_at TEXT NOT NULL,
			remark TEXT NOT NULL DEFAULT '',
			permissions TEXT NOT NULL,
			domains TEXT NOT NULL DEFAULT '*',
			is_admin BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS remark TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS domains TEXT NOT NULL DEFAULT '*'`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) ensureAdminUser(ctx context.Context) error {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM users WHERE is_admin = TRUE LIMIT 1`).Scan(&id)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	ts := nowISO()
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO users (name, token, expires_at, remark, permissions, domains, is_admin, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7, $8)
	`, s.cfg.AdminName, s.cfg.AdminToken, s.cfg.AdminExpiresAt, "", "manage,view,edit", "*", ts, ts)
	return err
}

func NewTokenCache(enabled bool, ttl time.Duration, maxSize int) *TokenCache {
	return &TokenCache{
		enabled: enabled,
		ttl:     ttl,
		maxSize: maxSize,
		items:   make(map[string]tokenCacheEntry),
	}
}

func (c *TokenCache) Get(token string) (User, bool) {
	if !c.enabled {
		return User{}, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.items[token]
	if !ok {
		return User{}, false
	}
	if time.Since(entry.CachedAt) > c.ttl {
		delete(c.items, token)
		return User{}, false
	}
	if expiresAt, err := parseISO(entry.User.ExpiresAt); err != nil || expiresAt.Before(time.Now().UTC()) {
		delete(c.items, token)
		if err == nil {
			return entry.User, true
		}
		return User{}, false
	}
	return entry.User, true
}

func (c *TokenCache) Set(user User) {
	if !c.enabled {
		return
	}
	token := strings.TrimSpace(user.Token)
	if token == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.maxSize > 0 && len(c.items) >= c.maxSize {
		var oldestToken string
		var oldestAt time.Time
		for cachedToken, entry := range c.items {
			if oldestToken == "" || entry.CachedAt.Before(oldestAt) {
				oldestToken = cachedToken
				oldestAt = entry.CachedAt
			}
		}
		if oldestToken != "" {
			delete(c.items, oldestToken)
		}
	}
	c.items[token] = tokenCacheEntry{User: user, CachedAt: time.Now()}
}

func (c *TokenCache) Invalidate(tokens ...string) {
	if !c.enabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, token := range tokens {
		delete(c.items, token)
	}
}

func (r *RateLimiter) Check(request *http.Request, scope string, maxRequests int, window time.Duration) int {
	if !r.enabled || maxRequests <= 0 || window <= 0 {
		return 0
	}

	clientIP := r.clientIP(request)
	if r.isWhitelisted(clientIP) {
		return 0
	}

	key := scope + "|" + clientIP
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	r.requestCount++
	if r.requestCount%256 == 0 {
		r.cleanup(now, window)
	}

	trimmed := trimTimes(r.hits[key], now, window)
	if len(trimmed) >= maxRequests {
		retryAfter := int(window.Seconds() - now.Sub(trimmed[0]).Seconds())
		if retryAfter < 1 {
			retryAfter = 1
		}
		r.hits[key] = trimmed
		return retryAfter
	}

	r.hits[key] = append(trimmed, now)
	return 0
}

func (r *RateLimiter) cleanup(now time.Time, defaultWindow time.Duration) {
	for key, hits := range r.hits {
		trimmed := trimTimes(hits, now, defaultWindow)
		if len(trimmed) == 0 {
			delete(r.hits, key)
			continue
		}
		r.hits[key] = trimmed
	}
}

func (r *RateLimiter) isWhitelisted(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return false
	}
	for _, allowed := range r.whitelistIPs {
		if allowed.Equal(ip) {
			return true
		}
	}
	for _, network := range r.whitelistNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *RateLimiter) clientIP(request *http.Request) string {
	if r.trustProxy {
		if header := strings.TrimSpace(request.Header.Get("X-Forwarded-For")); header != "" {
			if part := strings.TrimSpace(strings.Split(header, ",")[0]); part != "" {
				return part
			}
		}
	}
	host := strings.TrimSpace(request.RemoteAddr)
	if host == "" {
		return "unknown"
	}
	if parsedHost, _, ok := strings.Cut(host, ":"); ok && parsedHost != "" {
		return parsedHost
	}
	return host
}

func trimTimes(values []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	index := 0
	for index < len(values) && !values[index].After(cutoff) {
		index++
	}
	if index == 0 {
		return values
	}
	out := make([]time.Time, len(values)-index)
	copy(out, values[index:])
	return out
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", s.handleRoot)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /favicon.ico", s.handleFaviconICO)
	mux.HandleFunc("GET /favicon.svg", s.handleFaviconSVG)

	mux.HandleFunc("POST /api/login", s.handleAPILogin)
	mux.HandleFunc("POST /api/validate", s.handleAPIValidate)
	mux.HandleFunc("GET /api/me", s.handleAPIMe)
	mux.HandleFunc("GET /api/users", s.handleAPIUsersList)
	mux.HandleFunc("POST /api/users", s.handleAPIUsersCreate)
	mux.HandleFunc("PUT /api/users/{userID}", s.handleAPIUsersUpdate)
	mux.HandleFunc("DELETE /api/users/{userID}", s.handleAPIUsersDelete)

	mux.HandleFunc("GET /admin/login", s.handleAdminLoginPage)
	mux.HandleFunc("POST /admin/login", s.handleAdminLoginSubmit)
	mux.HandleFunc("GET /admin/logout", s.handleAdminLogout)
	mux.HandleFunc("GET /admin", s.handleAdminHome)
	mux.HandleFunc("GET /admin/", s.handleAdminHome)
	mux.HandleFunc("POST /admin/users", s.handleAdminUsersCreate)
	mux.HandleFunc("POST /admin/users/{userID}", s.handleAdminUsersUpdate)
	mux.HandleFunc("POST /admin/users/{userID}/delete", s.handleAdminUsersDelete)

	return loggingMiddleware(mux)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		log.Printf("%s %s %d %dms", r.Method, r.URL.RequestURI(), recorder.status, time.Since(start).Milliseconds())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.status = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleFaviconICO(w http.ResponseWriter, r *http.Request) {
	s.serveAsset(w, r, "favicon.ico", "image/x-icon")
}

func (s *Server) handleFaviconSVG(w http.ResponseWriter, r *http.Request) {
	s.serveAsset(w, r, "favicon.svg", "image/svg+xml")
}

func (s *Server) serveAsset(w http.ResponseWriter, _ *http.Request, name, contentType string) {
	data, err := fs.ReadFile(s.assets, name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

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

	if _, err := s.db.ExecContext(r.Context(), `DELETE FROM users WHERE id = $1`, userID); err != nil {
		s.internalError(w, err)
		return
	}
	s.tokenCache.Invalidate(user.Token)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

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

func (s *Server) currentUser(r *http.Request, permission string) (*User, int, string, error) {
	token := extractBearerToken(r)
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-Token"))
	}
	if token == "" {
		return nil, http.StatusUnauthorized, "missing token", nil
	}

	user, err := s.getUserByToken(r.Context(), token)
	if err != nil {
		return nil, 0, "", err
	}
	if user == nil {
		return nil, http.StatusUnauthorized, "invalid token", nil
	}
	if expired(*user) {
		return nil, http.StatusUnauthorized, "token expired", nil
	}
	if !hasPermission(*user, permission) {
		return nil, http.StatusForbidden, "forbidden", nil
	}
	return user, 0, "", nil
}

func (s *Server) adminFromSession(r *http.Request) (*User, bool, error) {
	userID, ok := s.readSessionCookie(r)
	if !ok {
		return nil, false, nil
	}
	user, err := s.findUserByID(r.Context(), userID)
	if err != nil {
		return nil, false, err
	}
	if user == nil || expired(*user) || !hasPermission(*user, "manage") {
		return nil, false, nil
	}
	return user, true, nil
}

func (s *Server) getUserByToken(ctx context.Context, token string) (*User, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, nil
	}
	if cached, ok := s.tokenCache.Get(token); ok {
		return &cached, nil
	}
	user, err := s.findUserByToken(ctx, token)
	if err != nil || user == nil {
		return user, err
	}
	s.tokenCache.Set(*user)
	return user, nil
}

func (s *Server) findUserByToken(ctx context.Context, token string) (*User, error) {
	query := `SELECT id, name, token, expires_at, remark, permissions, domains, created_at, updated_at, is_admin FROM users WHERE token = $1`
	return scanSingleUser(s.db.QueryRowContext(ctx, query, token))
}

func (s *Server) findUserByID(ctx context.Context, userID int64) (*User, error) {
	query := `SELECT id, name, token, expires_at, remark, permissions, domains, created_at, updated_at, is_admin FROM users WHERE id = $1`
	return scanSingleUser(s.db.QueryRowContext(ctx, query, userID))
}

func (s *Server) listUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, token, expires_at, remark, permissions, domains, created_at, updated_at, is_admin FROM users ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *Server) insertUser(ctx context.Context, payload normalizedUserPayload, isAdmin bool) error {
	ts := nowISO()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (name, token, expires_at, remark, permissions, domains, is_admin, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, payload.Name, payload.Token, payload.ExpiresAt, payload.Remark, strings.Join(payload.Permissions, ","), strings.Join(payload.Domains, ","), isAdmin, ts, ts)
	if err != nil {
		return err
	}
	s.tokenCache.Invalidate(payload.Token)
	return nil
}

func (s *Server) updateUser(ctx context.Context, userID int64, payload normalizedUserPayload, existing User) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET name = $1, token = $2, expires_at = $3, remark = $4, permissions = $5, domains = $6, updated_at = $7
		WHERE id = $8
	`, payload.Name, payload.Token, payload.ExpiresAt, payload.Remark, strings.Join(payload.Permissions, ","), strings.Join(payload.Domains, ","), nowISO(), userID)
	if err != nil {
		return err
	}
	s.tokenCache.Invalidate(existing.Token, payload.Token)
	return nil
}

func scanSingleUser(row *sql.Row) (*User, error) {
	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(sc scanner) (User, error) {
	var user User
	err := sc.Scan(
		&user.ID,
		&user.Name,
		&user.Token,
		&user.ExpiresAt,
		&user.Remark,
		&user.Permissions,
		&user.Domains,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.IsAdmin,
	)
	return user, err
}

func (u User) Public() PublicUser {
	return PublicUser{
		ID:          u.ID,
		Name:        u.Name,
		ExpiresAt:   u.ExpiresAt,
		Remark:      u.Remark,
		Permissions: normalizePermissions(u.Permissions),
		Domains:     normalizeDomains(u.Domains),
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
	}
}

func (u User) Full() FullUser {
	return FullUser{
		ID:          u.ID,
		Name:        u.Name,
		ExpiresAt:   u.ExpiresAt,
		Remark:      u.Remark,
		Token:       u.Token,
		Permissions: normalizePermissions(u.Permissions),
		Domains:     normalizeDomains(u.Domains),
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
		IsAdmin:     u.IsAdmin,
	}
}

type normalizedUserPayload struct {
	Name        string
	Token       string
	ExpiresAt   string
	Remark      string
	Permissions []string
	Domains     []string
}

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

func extractBearerToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return ""
	}
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	return ""
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

func (s *Server) setSessionCookie(w http.ResponseWriter, userID int64) {
	expiresAt := time.Now().Add(sessionTTL).Unix()
	payload := fmt.Sprintf("%d:%d", userID, expiresAt)
	signature := signHMAC(s.cfg.SecretKey, payload)
	value := base64.RawURLEncoding.EncodeToString([]byte(payload + "." + signature))
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(expiresAt, 0),
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func (s *Server) readSessionCookie(r *http.Request) (int64, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return 0, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return 0, false
	}
	parts := strings.SplitN(string(decoded), ".", 2)
	if len(parts) != 2 {
		return 0, false
	}
	payload, signature := parts[0], parts[1]
	if !hmac.Equal([]byte(signHMAC(s.cfg.SecretKey, payload)), []byte(signature)) {
		return 0, false
	}
	segments := strings.SplitN(payload, ":", 2)
	if len(segments) != 2 {
		return 0, false
	}
	userID, err := strconv.ParseInt(segments[0], 10, 64)
	if err != nil {
		return 0, false
	}
	expiresAt, err := strconv.ParseInt(segments[1], 10, 64)
	if err != nil || time.Now().Unix() > expiresAt {
		return 0, false
	}
	return userID, true
}

func signHMAC(secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

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

func (s *Server) internalError(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	writeDetailError(w, http.StatusInternalServerError, "internal server error")
}
