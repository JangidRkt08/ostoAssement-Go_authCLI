package auth

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/JangidRkt08/go-cli-auth/internal/database"
	"github.com/JangidRkt08/go-cli-auth/internal/security"
	"github.com/JangidRkt08/go-cli-auth/internal/session"
	"github.com/JangidRkt08/go-cli-auth/internal/user"
)

func setupTestService(t *testing.T) (*Service, *user.Repository, context.Context) {
	t.Helper()

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)

	t.Cleanup(cancel)

	pool, err := database.NewPool(ctx)
	if err != nil {
		t.Fatalf("database connection failed: %v", err)
	}

	t.Cleanup(pool.Close)

	userRepo := user.NewRepository(pool)
	sessionRepo := session.NewRepository(pool)

	return NewService(userRepo, sessionRepo), userRepo, ctx
}

func TestRegisterAndLogin(t *testing.T) {
	service, userRepo, ctx := setupTestService(t)

	username := "phase3_login_test"
	password := "correct-password-123"

	_, err := userRepo.FindByUsername(ctx, username)
	if err == nil {
		_, _ = service.Login(ctx, username, password)
		// Existing test data is cleaned below.
	}

	_, err = userRepo.Create(
		ctx,
		username,
		mustHashPassword(t, password),
	)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}

	t.Cleanup(func() {
		_ = userRepo.DeleteByUsername(ctx, username)
	})

	result, err := service.Login(ctx, username, password)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if result == nil {
		t.Fatal("Login() returned nil result")
	}

	if result.SessionID.String() == "" {
		t.Fatal("Login() returned empty session ID")
	}

	if !result.ExpiresAt.After(time.Now()) {
		t.Fatal("session expiration must be in the future")
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	service, userRepo, ctx := setupTestService(t)

	username := "phase3_wrong_password"
	password := "correct-password-123"

	_, err := userRepo.Create(
		ctx,
		username,
		mustHashPassword(t, password),
	)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}

	t.Cleanup(func() {
		_ = userRepo.DeleteByUsername(ctx, username)
	})

	_, err = service.Login(ctx, username, "wrong-password")

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf(
			"expected ErrInvalidCredentials, got %v",
			err,
		)
	}
}

func TestLoginLocksAccountAfterFiveFailures(t *testing.T) {
	service, userRepo, ctx := setupTestService(t)

	username := "phase3_lockout_test"
	password := "correct-password-123"

	_, err := userRepo.Create(
		ctx,
		username,
		mustHashPassword(t, password),
	)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}

	t.Cleanup(func() {
		_ = userRepo.DeleteByUsername(ctx, username)
	})

	for i := 1; i <= 5; i++ {
		_, err := service.Login(
			ctx,
			username,
			"definitely-wrong-password",
		)

		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf(
				"attempt %d: expected ErrInvalidCredentials, got %v",
				i,
				err,
			)
		}
	}

	_, err = service.Login(ctx, username, password)

	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf(
			"expected ErrAccountLocked after five failures, got %v",
			err,
		)
	}
}

func TestSuccessfulLoginResetsFailedAttempts(t *testing.T) {
	service, userRepo, ctx := setupTestService(t)

	username := "phase3_reset_test"
	password := "correct-password-123"

	_, err := userRepo.Create(
		ctx,
		username,
		mustHashPassword(t, password),
	)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}

	t.Cleanup(func() {
		_ = userRepo.DeleteByUsername(ctx, username)
	})

	// Cause two failed attempts.
	for i := 0; i < 2; i++ {
		_, err := service.Login(
			ctx,
			username,
			"wrong-password",
		)

		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf(
				"expected invalid credentials, got %v",
				err,
			)
		}
	}

	// Correct login should reset the counter.
	_, err = service.Login(ctx, username, password)
	if err != nil {
		t.Fatalf("successful Login() error = %v", err)
	}

	u, err := userRepo.FindByUsername(ctx, username)
	if err != nil {
		t.Fatalf("FindByUsername() error = %v", err)
	}

	if u.FailedLoginAttempts != 0 {
		t.Fatalf(
			"failed login attempts = %d, want 0",
			u.FailedLoginAttempts,
		)
	}

	if u.LockedUntil != nil {
		t.Fatal("successful login should clear locked_until")
	}

	if u.LastLoginAt == nil {
		t.Fatal("successful login should set last_login_at")
	}
}

func mustHashPassword(t *testing.T, password string) string {
	t.Helper()

	hash, err := security.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	return hash
}
