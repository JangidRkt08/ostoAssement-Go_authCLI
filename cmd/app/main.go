package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/JangidRkt08/go-cli-auth/internal/api"
	"github.com/JangidRkt08/go-cli-auth/internal/auth"
	"github.com/JangidRkt08/go-cli-auth/internal/cli"
	"github.com/JangidRkt08/go-cli-auth/internal/database"
	"github.com/JangidRkt08/go-cli-auth/internal/session"
	"github.com/JangidRkt08/go-cli-auth/internal/user"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := database.NewPool(ctx)
	if err != nil {
		logger.Fatalf("database initialization failed: %v", err)
	}
	defer pool.Close()
	userRepository := user.NewRepository(pool)
	sessionRepository := session.NewRepository(pool)

	authService := auth.NewService(
		userRepository,
		sessionRepository,
	)

	handler := api.NewHandler(authService, userRepository, sessionRepository)

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/auth/register", handler.Register)
	mux.HandleFunc("POST /api/v1/auth/login", handler.Login)

	mux.Handle("GET /api/v1/me",
		api.WithAuthentication(sessionRepository, http.HandlerFunc(handler.Me)))

	mux.HandleFunc("POST /api/v1/auth/logout", handler.Logout)
	mux.Handle("POST /api/v1/auth/mfa/setup",
		api.WithAuthentication(sessionRepository, http.HandlerFunc(handler.SetupMFA)),
	)

	mux.Handle("POST /api/v1/auth/mfa/verify",
		api.WithAuthentication(sessionRepository, http.HandlerFunc(handler.VerifyMFA)),
	)

	mux.Handle("POST /api/v1/auth/mfa/disable",
		api.WithAuthentication(sessionRepository, http.HandlerFunc(handler.DisableMFA)),
	)

	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Println("HTTP server listening on :8080")

		if err := server.ListenAndServe(); err != nil &&
			err != http.ErrServerClosed {
			logger.Fatalf("HTTP server failed: %v", err)
		}
	}()

	logger.Println("database connection successful")

	commandLine := cli.New()

	commandLine.RegisterBuiltInCommands()

	commandLine.RegisterCommand(cli.Command{
		Name:        "help",
		Description: "show available commands",
		Handler: func(ctx context.Context, args []string) error {
			fmt.Println("Available commands:")
			fmt.Println("  register       Create a new account")
			fmt.Println("  login          Login to your account")
			fmt.Println("  whoami         Show current user")
			fmt.Println("  enable-2fa     Enable two-factor authentication")
			fmt.Println("  disable-2fa    Disable two-factor authentication")
			fmt.Println("  logout         Logout")
			fmt.Println("  help            Show this help")
			fmt.Println("  exit            Exit the application")
			return nil
		},
	})

	commandLine.RegisterCommand(cli.Command{
		Name:        "register",
		Description: "Create a new account",
		Handler: func(ctx context.Context, args []string) error {
			return commandLine.Register(ctx, args)
		},
	})

	if err := commandLine.Run(context.Background()); err != nil {
		logger.Fatalf("CLI failed: %v", err)
	}

}
