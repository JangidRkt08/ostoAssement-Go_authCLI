package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUserNotFound   = errors.New("user not found")
	ErrUsernameExists = errors.New("username already exists")
)

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) FindByUsername(
	ctx context.Context,
	username string,
) (*User, error) {
	const query = `
		SELECT
			id,
			username,
			password_hash,
			totp_secret,
			mfa_enabled,
			failed_login_attempts,
			locked_until,
			created_at,
			last_login_at
		FROM users
		WHERE username = $1
	`

	var u User

	err := r.db.QueryRow(ctx, query, username).Scan(
		&u.ID,
		&u.Username,
		&u.PasswordHash,
		&u.TOTPSecret,
		&u.MFAEnabled,
		&u.FailedLoginAttempts,
		&u.LockedUntil,
		&u.CreatedAt,
		&u.LastLoginAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("find user by username: %w", err)
	}

	return &u, nil
}

func (r *Repository) Create(
	ctx context.Context,
	username string,
	passwordHash string,
) (*User, error) {
	const query = `
		INSERT INTO users (
			username,
			password_hash
		)
		VALUES ($1, $2)
		RETURNING
			id,
			username,
			password_hash,
			totp_secret,
			mfa_enabled,
			failed_login_attempts,
			locked_until,
			created_at,
			last_login_at
	`

	var u User

	err := r.db.QueryRow(
		ctx,
		query,
		username,
		passwordHash,
	).Scan(
		&u.ID,
		&u.Username,
		&u.PasswordHash,
		&u.TOTPSecret,
		&u.MFAEnabled,
		&u.FailedLoginAttempts,
		&u.LockedUntil,
		&u.CreatedAt,
		&u.LastLoginAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrUsernameExists
		}

		return nil, fmt.Errorf("create user: %w", err)
	}

	return &u, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError

	if !errors.As(err, &pgErr) {
		return false
	}

	return pgErr.Code == "23505"
}
