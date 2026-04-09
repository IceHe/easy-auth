package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

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
