package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

const userSelectColumns = `id, name, token, expires_at, remark, permissions, domains, created_at, updated_at, is_admin, deleted_at`

func (s *Server) findUserByToken(ctx context.Context, token string) (*User, error) {
	query := `SELECT ` + userSelectColumns + ` FROM users WHERE token = $1 AND deleted_at = ''`
	return scanSingleUser(s.db.QueryRowContext(ctx, query, token))
}

func (s *Server) findUserByID(ctx context.Context, userID int64) (*User, error) {
	query := `SELECT ` + userSelectColumns + ` FROM users WHERE id = $1 AND deleted_at = ''`
	return scanSingleUser(s.db.QueryRowContext(ctx, query, userID))
}

func (s *Server) findAnyUserByID(ctx context.Context, userID int64) (*User, error) {
	query := `SELECT ` + userSelectColumns + ` FROM users WHERE id = $1`
	return scanSingleUser(s.db.QueryRowContext(ctx, query, userID))
}

func (s *Server) listUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userSelectColumns+` FROM users WHERE deleted_at = '' ORDER BY id ASC`)
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

func (s *Server) listDeletedUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userSelectColumns+` FROM users WHERE deleted_at <> '' ORDER BY deleted_at DESC, id DESC`)
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
	result, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET name = $1, token = $2, expires_at = $3, remark = $4, permissions = $5, domains = $6, updated_at = $7
		WHERE id = $8 AND deleted_at = ''
	`, payload.Name, payload.Token, payload.ExpiresAt, payload.Remark, strings.Join(payload.Permissions, ","), strings.Join(payload.Domains, ","), nowISO(), userID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}
	s.tokenCache.Invalidate(existing.Token, payload.Token)
	return nil
}

func (s *Server) softDeleteUser(ctx context.Context, user User) error {
	ts := nowISO()
	result, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET deleted_at = $1, updated_at = $1
		WHERE id = $2 AND deleted_at = ''
	`, ts, user.ID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}
	s.tokenCache.Invalidate(user.Token)
	return nil
}

func (s *Server) restoreUser(ctx context.Context, user User) error {
	ts := nowISO()
	result, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET deleted_at = '', updated_at = $1
		WHERE id = $2 AND deleted_at <> ''
	`, ts, user.ID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}
	s.tokenCache.Invalidate(user.Token)
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
		&user.DeletedAt,
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
