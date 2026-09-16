package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	AppName    string
	AppVersion string
	AppEnv     string
	AppHost    string
	AppPort    int

	DatabaseHost     string
	DatabasePort     int
	DatabaseName     string
	DatabaseUser     string
	DatabasePassword string
	DatabaseSSLMode  string

	JWTSecret          string
	JWTIssuer          string
	JWTExpirationHours int
}

func Load() (Config, error) {
	port, err := strconv.Atoi(getEnv("APP_PORT", "8080"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid APP_PORT: %w", err)
	}

	databasePort, err := strconv.Atoi(getEnv("DATABASE_PORT", "5432"))
	if err != nil {
		return Config{}, fmt.Errorf("invalid DATABASE_PORT: %w", err)
	}

	jwtExpirationHours, err := strconv.Atoi(
		getEnv("JWT_EXPIRATION_HOURS", "24"),
	)
	if err != nil {
		return Config{}, fmt.Errorf(
			"invalid JWT_EXPIRATION_HOURS: %w",
			err,
		)
	}

	if jwtExpirationHours <= 0 {
		return Config{}, fmt.Errorf(
			"JWT_EXPIRATION_HOURS must be greater than zero",
		)
	}

	cfg := Config{
		AppName:    getEnv("APP_NAME", "NEXUS API"),
		AppVersion: getEnv("APP_VERSION", "0.2.0"),
		AppEnv:     getEnv("APP_ENV", "development"),
		AppHost:    getEnv("APP_HOST", "127.0.0.1"),
		AppPort:    port,

		DatabaseHost:     getEnv("DATABASE_HOST", "localhost"),
		DatabasePort:     databasePort,
		DatabaseName:     getEnv("DATABASE_NAME", "nexus"),
		DatabaseUser:     getEnv("DATABASE_USER", "nexus_app"),
		DatabasePassword: os.Getenv("DATABASE_PASSWORD"),
		DatabaseSSLMode:  getEnv("DATABASE_SSLMODE", "disable"),

		JWTSecret:          os.Getenv("JWT_SECRET"),
		JWTIssuer:          getEnv("JWT_ISSUER", "nexus-api"),
		JWTExpirationHours: jwtExpirationHours,
	}

	if cfg.DatabasePassword == "" {
		return Config{}, fmt.Errorf("DATABASE_PASSWORD is required")
	}

	if cfg.JWTSecret == "" {
		return Config{}, fmt.Errorf("JWT_SECRET is required")
	}

	if len(cfg.JWTSecret) < 32 {
		return Config{}, fmt.Errorf(
			"JWT_SECRET must be at least 32 characters",
		)
	}

	if cfg.JWTIssuer == "" {
		return Config{}, fmt.Errorf("JWT_ISSUER is required")
	}

	return cfg, nil
}

func (c Config) DatabaseURL() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.DatabaseUser,
		c.DatabasePassword,
		c.DatabaseHost,
		c.DatabasePort,
		c.DatabaseName,
		c.DatabaseSSLMode,
	)
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)

	if value == "" {
		return fallback
	}

	return value
}
