package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/JangidRkt08/go-cli-auth/internal/security"
	"github.com/JangidRkt08/go-cli-auth/internal/session"
	"github.com/JangidRkt08/go-cli-auth/internal/user"
	"github.com/google/uuid"
)

var (
	ErrInvalidUsername    = errors.New("invalid username")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account is temporarily locked")
)

const (
	maxLoginAttempts = 5
	lockoutDuration  = 15 * time.Minute
	sessionDuration  = 30 * time.Minute
)

type LoginResult struct {
	SessionID uuid.UUID
	ExpiresAt time.Time
}

type Service struct {
	users    *user.Repository
	sessions *session.Repository
}

func NewService(users *user.Repository, sessions *session.Repository) *Service {
	return &Service{
		users:    users,
		sessions: sessions,
	}
}

func (s *Service) Register(ctx context.Context, username string, password string) (*user.User, error) {
	username = strings.TrimSpace(username)

	if err := validateUsername(username); err != nil {
		return nil, err
	}

	if err := validatePassword(password); err != nil {
		return nil, err
	}

	passwordHash, err := security.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("register user: %w", err)
	}

	newUser, err := s.users.Create(
		ctx,
		username,
		passwordHash,
	)
	if err != nil {
		return nil, err
	}

	return newUser, nil
}

func validateUsername(username string) error {
	if len(username) < 3 || len(username) > 50 {
		return ErrInvalidUsername
	}

	for _, r := range username {
		if !(r >= 'a' && r <= 'z' ||
			r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' ||
			r == '_' ||
			r == '-') {
			return ErrInvalidUsername
		}
	}

	return nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return ErrInvalidPassword
	}

	return nil
}

func (s *Service) Login(ctx context.Context, username string, password string) (*LoginResult, error) {
	username = strings.TrimSpace(username)

	u, err := s.users.FindByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}

		return nil, fmt.Errorf("login: %w", err)
	}

	if u.LockedUntil != nil && time.Now().UTC().Before(*u.LockedUntil) {
		return nil, ErrAccountLocked
	}

	if !security.CheckPassword(password, u.PasswordHash) {
		if err := s.users.IncrementFailedAttempts(
			ctx,
			u.ID,
			lockoutDuration,
			maxLoginAttempts,
		); err != nil {
			return nil, fmt.Errorf("login failure handling: %w", err)
		}

		return nil, ErrInvalidCredentials
	}

	if err := s.users.ResetFailedAttempts(ctx, u.ID); err != nil {
		return nil, fmt.Errorf("reset login attempts: %w", err)
	}

	newSession, err := s.sessions.Create(
		ctx,
		u.ID,
		sessionDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("login session: %w", err)
	}

	return &LoginResult{
		SessionID: newSession.ID,
		ExpiresAt: newSession.ExpiresAt,
	}, nil
}
