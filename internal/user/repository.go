package user

import (
	"context"
	"errors"
	"fmt"
	"time"

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

func (r *Repository) IncrementFailedAttempts(ctx context.Context, userID int64, lockDuration time.Duration, maxAttempts int) error {
	const query = `
		UPDATE users
		SET
			failed_login_attempts = failed_login_attempts + 1,
			locked_until = CASE
							WHEN failed_login_attempts + 1 >= $2
							THEN NOW() + ($3 * INTERVAL '1 second')
							ELSE locked_until
						   END
		WHERE id = $1
	`

	_, err := r.db.Exec(
		ctx,
		query,
		userID,
		maxAttempts,
		lockDuration.Seconds(),
	)

	if err != nil {
		return fmt.Errorf("increment failed attempts: %w", err)
	}

	return nil
}

func (r *Repository) ResetFailedAttempts(
	ctx context.Context,
	userID int64,
) error {
	const query = `
		UPDATE users
		SET
			failed_login_attempts = 0,
			locked_until = NULL,
			last_login_at = NOW()
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("reset failed attempts: %w", err)
	}

	return nil
}

func (r *Repository) DeleteByUsername(
	ctx context.Context,
	username string,
) error {
	const query = `
		DELETE FROM users
		WHERE username = $1
	`

	_, err := r.db.Exec(ctx, query, username)
	if err != nil {
		return fmt.Errorf("delete user by username: %w", err)
	}

	return nil
}

func (r *Repository) FindByID(ctx context.Context, id int64) (*User, error) {
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
		WHERE id = $1
	`

	var u User

	err := r.db.QueryRow(ctx, query, id).Scan(
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
		return nil, fmt.Errorf("find user by id: %w", err)
	}

	return &u, nil
}

func (r *Repository) SetTOTPSecret(
	ctx context.Context,
	userID int64,
	secret string,
) error {
	const query = `
		UPDATE users
		SET totp_secret = $1
		WHERE id = $2
	`

	_, err := r.db.Exec(ctx, query, secret, userID)
	if err != nil {
		return fmt.Errorf("set totp secret: %w", err)
	}

	return nil
}

func (r *Repository) EnableMFA(
	ctx context.Context,
	userID int64,
) error {
	const query = `
		UPDATE users
		SET mfa_enabled = TRUE
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("enable MFA: %w", err)
	}

	return nil
}

func (r *Repository) DisableMFA(
	ctx context.Context,
	userID int64,
) error {
	const query = `
		UPDATE users
		SET
			mfa_enabled = FALSE,
			totp_secret = NULL
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("disable MFA: %w", err)
	}

	return nil
}
