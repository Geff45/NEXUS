package users

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInactiveUser       = errors.New("user account is inactive")
)

type Service struct {
	repository Repository
}

func NewService(repository Repository) *Service {
	return &Service{
		repository: repository,
	}
}

func (s *Service) Register(
	ctx context.Context,
	username string,
	email string,
	password string,
) (*User, error) {
	username = strings.TrimSpace(username)
	email = strings.ToLower(strings.TrimSpace(email))

	if username == "" {
		return nil, errors.New("username is required")
	}

	if email == "" {
		return nil, errors.New("email is required")
	}

	if len(password) < 8 {
		return nil, errors.New("password must be at least 8 characters")
	}

	_, err := s.repository.FindByUsername(ctx, username)
	if err == nil {
		return nil, ErrUsernameExists
	}

	if !errors.Is(err, ErrUserNotFound) {
		return nil, fmt.Errorf("check username: %w", err)
	}

	_, err = s.repository.FindByEmail(ctx, email)
	if err == nil {
		return nil, ErrEmailExists
	}

	if !errors.Is(err, ErrUserNotFound) {
		return nil, fmt.Errorf("check email: %w", err)
	}

	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user := &User{
		ID:            uuid.Nil,
		Username:      username,
		Email:         email,
		PasswordHash:  string(passwordHash),
		Status:        "active",
		EmailVerified: false,
		PhoneVerified: false,
		IsCreator:     false,
		IsAdmin:       false,
	}

	if err := s.repository.Create(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *Service) Authenticate(
	ctx context.Context,
	login string,
	password string,
) (*User, error) {
	login = strings.TrimSpace(login)

	var (
		user *User
		err  error
	)

	if strings.Contains(login, "@") {
		user, err = s.repository.FindByEmail(
			ctx,
			strings.ToLower(login),
		)
	} else {
		user, err = s.repository.FindByUsername(
			ctx,
			login,
		)
	}

	if errors.Is(err, ErrUserNotFound) {
		return nil, ErrInvalidCredentials
	}

	if err != nil {
		return nil, err
	}

	if user.Status != "active" {
		return nil, ErrInactiveUser
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.PasswordHash),
		[]byte(password),
	); err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := s.repository.UpdateLastLogin(
		ctx,
		user.ID,
	); err != nil {
		return nil, fmt.Errorf("update login time: %w", err)
	}

	return user, nil
}

func (s *Service) GetByID(
	ctx context.Context,
	id uuid.UUID,
) (*User, error) {
	if id == uuid.Nil {
		return nil, ErrUserNotFound
	}

	user, err := s.repository.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *Service) ResetPassword(
	ctx context.Context,
	id uuid.UUID,
	password string,
) error {
	if id == uuid.Nil {
		return ErrUserNotFound
	}

	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	return s.repository.UpdatePassword(
		ctx,
		id,
		string(passwordHash),
	)
}
