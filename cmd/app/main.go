package main

import (
	"context"
	"log"
	"os"
	"time"

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

	_ = auth.NewService(
		userRepository,
		sessionRepository,
	)

	logger.Println("database connection successful")
	logger.Println("application initialization successful")
}
