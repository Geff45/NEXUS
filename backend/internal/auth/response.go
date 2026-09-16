package auth

import (
	"time"

	"github.com/google/uuid"
)

type ErrorResponse struct {
	Error string `json:"error"`
}

type UserResponse struct {
	ID            uuid.UUID `json:"id"`
	Username      string    `json:"username"`
	Email         string    `json:"email"`
	Status        string    `json:"status"`
	EmailVerified bool      `json:"email_verified"`
	PhoneVerified bool      `json:"phone_verified"`
	IsCreator     bool      `json:"is_creator"`
	IsAdmin       bool      `json:"is_admin"`
	CreatedAt     time.Time `json:"created_at"`
}

type RegisterResponse struct {
	User UserResponse `json:"user"`
}

type LoginResponse struct {
	User    UserResponse `json:"user"`
	Token   string       `json:"token"`
	Session uuid.UUID    `json:"session_id"`
}

type LogoutResponse struct {
	Message string `json:"message"`
}
