package main

import (
	"net"
	"net/http"
	"strings"
	"time"
)

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
