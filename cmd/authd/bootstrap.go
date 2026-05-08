package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

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
			updated_at TEXT NOT NULL,
			deleted_at TEXT NOT NULL DEFAULT ''
		)`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS remark TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS domains TEXT NOT NULL DEFAULT '*'`,
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TEXT NOT NULL DEFAULT ''`,
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
