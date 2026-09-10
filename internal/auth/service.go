package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/JangidRkt08/go-cli-auth/internal/security"
	"github.com/JangidRkt08/go-cli-auth/internal/user"
)

var (
	ErrInvalidUsername = errors.New("invalid username")
	ErrInvalidPassword = errors.New("invalid password")
)

type Service struct {
	users *user.Repository
}

func NewService(users *user.Repository) *Service {
	return &Service{
		users: users,
	}
}

func (s *Service) Register(
	ctx context.Context,
	username string,
	password string,
) (*user.User, error) {
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
