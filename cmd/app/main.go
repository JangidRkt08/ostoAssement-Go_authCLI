package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/JangidRkt08/go-cli-auth/internal/api"
	"github.com/JangidRkt08/go-cli-auth/internal/auth"
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

	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logger.Println("database connection successful")
	logger.Println("HTTP server listening on :8080")
	if err := server.ListenAndServe(); err != nil &&
		err != http.ErrServerClosed {
		logger.Fatalf("HTTP server failed: %v", err)
	}
}
