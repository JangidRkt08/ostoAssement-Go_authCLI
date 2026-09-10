package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/JangidRkt08/go-cli-auth/internal/database"
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

	logger.Println("database connection successful")
}
