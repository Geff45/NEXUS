package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"nexus/internal/auth"
	"nexus/internal/config"
	"nexus/internal/database"
	"nexus/internal/sessions"
	"nexus/internal/token"
	"nexus/internal/users"
)

type HealthResponse struct {
	Status   string `json:"status"`
	Service  string `json:"service"`
	Version  string `json:"version"`
	Database string `json:"database"`
}

func healthHandler(
	db *database.Database,
	cfg config.Config,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(
				w,
				"method not allowed",
				http.StatusMethodNotAllowed,
			)
			return
		}

		ctx, cancel := context.WithTimeout(
			r.Context(),
			2*time.Second,
		)
		defer cancel()

		databaseStatus := "ok"

		if err := db.Pool.Ping(ctx); err != nil {
			databaseStatus = "error"
		}

		response := HealthResponse{
			Status:   "ok",
			Service:  "nexus-api",
			Version:  cfg.AppVersion,
			Database: databaseStatus,
		}

		w.Header().Set(
			"Content-Type",
			"application/json",
		)

		if databaseStatus != "ok" {
			w.WriteHeader(
				http.StatusServiceUnavailable,
			)
		}

		if err := json.NewEncoder(w).Encode(
			response,
		); err != nil {
			log.Printf(
				"failed to encode health response: %v",
				err,
			)
		}
	}
}

func loadEnvironment() {
	workingDir, err := os.Getwd()

	if err != nil {
		log.Printf(
			"could not determine working directory: %v",
			err,
		)
		return
	}

	envPath := filepath.Join(
		workingDir,
		".env",
	)

	if _, err := os.Stat(envPath); err != nil {
		if os.IsNotExist(err) {
			log.Printf(
				".env not found at %s; using system environment variables",
				envPath,
			)
		} else {
			log.Printf(
				"could not access .env at %s: %v",
				envPath,
				err,
			)
		}

		return
	}

	if err := godotenv.Overload(
		envPath,
	); err != nil {
		log.Fatalf(
			"failed to load .env from %s: %v",
			envPath,
			err,
		)
	}

	log.Printf(
		"Environment loaded from %s",
		envPath,
	)
}

func main() {
	loadEnvironment()

	cfg, err := config.Load()

	if err != nil {
		log.Fatalf(
			"configuration error: %v",
			err,
		)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	db, err := database.Connect(
		ctx,
		cfg,
	)

	if err != nil {
		log.Fatalf(
			"database connection error: %v",
			err,
		)
	}

	defer db.Close()

	userRepository := users.NewPostgresRepository(
		db.Pool,
	)

	userService := users.NewService(
		userRepository,
	)

	sessionRepository := sessions.NewPostgresRepository(
		db.Pool,
	)

	sessionService := sessions.NewService(
		sessionRepository,
		7*24*time.Hour,
	)

	tokenManager, err := token.NewManager(
		cfg.JWTSecret,
		cfg.JWTIssuer,
		time.Duration(
			cfg.JWTExpirationHours,
		)*time.Hour,
	)

	if err != nil {
		log.Fatalf(
			"JWT configuration error: %v",
			err,
		)
	}

	authHandler := auth.NewHandler(
		userService,
		tokenManager,
		sessionService,
	)

	mux := http.NewServeMux()

	mux.HandleFunc(
		"/health",
		healthHandler(db, cfg),
	)

	mux.HandleFunc(
		"/api/v1/auth/register",
		authHandler.Register,
	)

	mux.HandleFunc(
		"/api/v1/auth/login",
		authHandler.Login,
	)

	protectedMe := auth.JWTMiddleware(
		tokenManager,
		sessionService,
		http.HandlerFunc(
			authHandler.Me,
		),
	)

	mux.Handle(
		"/api/v1/me",
		protectedMe,
	)

	protectedLogout := auth.JWTMiddleware(
		tokenManager,
		sessionService,
		http.HandlerFunc(
			authHandler.Logout,
		),
	)

	mux.Handle(
		"/api/v1/auth/logout",
		protectedLogout,
	)

	protectedLogoutAll := auth.JWTMiddleware(
		tokenManager,
		sessionService,
		http.HandlerFunc(
			authHandler.LogoutAll,
		),
	)

	mux.Handle(
		"/api/v1/auth/logout-all",
		protectedLogoutAll,
	)

	server := &http.Server{
		Addr: fmt.Sprintf(
			"%s:%d",
			cfg.AppHost,
			cfg.AppPort,
		),

		Handler: mux,

		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Println(
		"========================================",
	)
	log.Printf(
		"             %s",
		cfg.AppName,
	)
	log.Println(
		"========================================",
	)

	log.Printf(
		"Version     : %s",
		cfg.AppVersion,
	)

	log.Printf(
		"Environment : %s",
		cfg.AppEnv,
	)

	log.Printf(
		"Address     : http://%s:%d",
		cfg.AppHost,
		cfg.AppPort,
	)

	log.Printf(
		"Health      : GET /health",
	)

	log.Printf(
		"Register    : POST /api/v1/auth/register",
	)

	log.Printf(
		"Login       : POST /api/v1/auth/login",
	)

	log.Printf(
		"Me          : GET /api/v1/me",
	)

	log.Printf(
		"Logout      : POST /api/v1/auth/logout",
	)

	log.Printf(
		"Logout All   : POST /api/v1/auth/logout-all",
	)

	log.Printf(
		"JWT         : HS256",
	)

	log.Printf(
		"JWT issuer  : %s",
		cfg.JWTIssuer,
	)

	log.Printf(
		"JWT expiry  : %d hours",
		cfg.JWTExpirationHours,
	)

	log.Println(
		"Sessions    : PostgreSQL",
	)

	log.Println(
		"Database    : PostgreSQL",
	)

	log.Println(
		"========================================",
	)

	log.Println(
		"NEXUS API starting...",
	)

	go func() {
		if err := server.ListenAndServe(); err != nil &&
			err != http.ErrServerClosed {

			log.Fatalf(
				"server error: %v",
				err,
			)
		}
	}()

	<-ctx.Done()

	log.Println(
		"Shutdown signal received...",
	)

	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	if err := server.Shutdown(
		shutdownCtx,
	); err != nil {
		log.Printf(
			"server shutdown error: %v",
			err,
		)
	}

	log.Println(
		"NEXUS API stopped.",
	)
}
