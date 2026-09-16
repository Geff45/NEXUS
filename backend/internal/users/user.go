package users

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID            uuid.UUID
	Username      string
	Email         string
	PasswordHash  string
	Status        string
	EmailVerified bool
	PhoneVerified bool
	IsCreator     bool
	IsAdmin       bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
	LastLoginAt   *time.Time
}

type Repository interface {
	Create(ctx context.Context, user *User) error
	FindByID(ctx context.Context, id uuid.UUID) (*User, error)
	FindByUsername(ctx context.Context, username string) (*User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error
}
