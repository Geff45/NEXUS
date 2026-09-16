package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"

	"nexus/internal/config"
	"nexus/internal/users"
)

func main() {
	log.SetFlags(log.LstdFlags)

	if err := godotenv.Load(".env"); err != nil {
		log.Printf("warning: .env not loaded: %v", err)
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	if cfg.AppEnv != "development" {
		log.Fatalf(
			"reset-password is disabled outside development environment",
		)
	}

	if len(os.Args) != 3 {
		fmt.Println("Usage:")
		fmt.Println(
			"  go run .\\cmd\\reset-password <username> <new-password>",
		)
		fmt.Println()
		fmt.Println("Example:")
		fmt.Println(
			"  go run .\\cmd\\reset-password nexus_test <new-password>",
		)
		os.Exit(1)
	}

	username := os.Args[1]
	newPassword := os.Args[2]

	if len(newPassword) < 8 {
		log.Fatal("password must be at least 8 characters")
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	pool, err := pgxpool.New(
		ctx,
		cfg.DatabaseURL(),
	)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("database ping failed: %v", err)
	}

	repository := users.NewPostgresRepository(pool)
	service := users.NewService(repository)

	user, err := repository.FindByUsername(
		ctx,
		username,
	)
	if err != nil {
		log.Fatalf("find user: %v", err)
	}

	if err := service.ResetPassword(
		ctx,
		user.ID,
		newPassword,
	); err != nil {
		log.Fatalf("reset password: %v", err)
	}

	fmt.Println()
	fmt.Println("======================================")
	fmt.Println(" NEXUS PASSWORD RESET SUCCESSFUL")
	fmt.Println("======================================")
	fmt.Printf("Username: %s\n", user.Username)
	fmt.Printf("User ID : %s\n", user.ID)
	fmt.Println("======================================")
}
