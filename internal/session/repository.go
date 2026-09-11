package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrSessionNotFound = errors.New("session not found")

type Session struct {
	ID        uuid.UUID
	UserID    int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(
	ctx context.Context,
	userID int64,
	duration time.Duration,
) (*Session, error) {
	id := uuid.New()
	now := time.Now().UTC()
	expiresAt := now.Add(duration)

	const query = `
		INSERT INTO sessions (
			id,
			user_id,
			created_at,
			expires_at
		)
		VALUES ($1, $2, $3, $4)
		RETURNING id, user_id, created_at, expires_at
	`

	var s Session

	err := r.db.QueryRow(
		ctx,
		query,
		id,
		userID,
		now,
		expiresAt,
	).Scan(
		&s.ID,
		&s.UserID,
		&s.CreatedAt,
		&s.ExpiresAt,
	)

	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return &s, nil
}

func (r *Repository) FindByID(
	ctx context.Context,
	id uuid.UUID,
) (*Session, error) {
	const query = `
		SELECT
			id,
			user_id,
			created_at,
			expires_at
		FROM sessions
		WHERE id = $1
	`

	var s Session

	err := r.db.QueryRow(ctx, query, id).Scan(
		&s.ID,
		&s.UserID,
		&s.CreatedAt,
		&s.ExpiresAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("find session: %w", err)
	}

	return &s, nil
}

func (r *Repository) Delete(
	ctx context.Context,
	id uuid.UUID,
) error {
	const query = `
		DELETE FROM sessions
		WHERE id = $1
	`

	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}
