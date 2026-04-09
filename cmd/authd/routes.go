package main

import (
	"io/fs"
	"log"
	"net/http"
	"time"
)

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
