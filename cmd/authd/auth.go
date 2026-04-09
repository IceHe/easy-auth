package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

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
