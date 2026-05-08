package main

import (
	"database/sql"
	"embed"
	"io/fs"
	"net"
	"sync"
	"time"
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
	DeletedAt   string `json:"-"`
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

type normalizedUserPayload struct {
	Name        string
	Token       string
	ExpiresAt   string
	Remark      string
	Permissions []string
	Domains     []string
}

type scanner interface {
	Scan(dest ...any) error
}
