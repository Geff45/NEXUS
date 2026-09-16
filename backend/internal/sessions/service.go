package sessions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	DefaultExpiration = 7 * 24 * time.Hour
	TokenBytes        = 32
)

type Service struct {
	repository Repository
	expiration time.Duration
}

func NewService(
	repository Repository,
	expiration time.Duration,
) *Service {
	if expiration <= 0 {
		expiration = DefaultExpiration
	}

	return &Service{
		repository: repository,
		expiration: expiration,
	}
}

func (s *Service) Create(
	ctx context.Context,
	userID uuid.UUID,
	userAgent string,
	ipAddress string,
) (*Session, string, error) {
	if userID == uuid.Nil {
		return nil, "", errors.New("user id is required")
	}

	rawToken, err := generateToken()
	if err != nil {
		return nil, "", fmt.Errorf("generate session token: %w", err)
	}

	tokenHash := HashToken(rawToken)

	session := &Session{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: tokenHash,
		UserAgent: strings.TrimSpace(userAgent),
		IPAddress: normalizeIPAddress(ipAddress),
		ExpiresAt: time.Now().Add(s.expiration),
	}

	if err := s.repository.Create(ctx, session); err != nil {
		return nil, "", err
	}

	return session, rawToken, nil
}

func (s *Service) GetByID(
	ctx context.Context,
	id uuid.UUID,
) (*Session, error) {
	if id == uuid.Nil {
		return nil, ErrSessionNotFound
	}

	session, err := s.repository.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if session.IsRevoked() {
		return nil, ErrSessionRevoked
	}

	if session.IsExpired() {
		return nil, ErrSessionExpired
	}

	return session, nil
}

func (s *Service) GetByToken(
	ctx context.Context,
	rawToken string,
) (*Session, error) {
	rawToken = strings.TrimSpace(rawToken)

	if rawToken == "" {
		return nil, ErrSessionNotFound
	}

	session, err := s.repository.FindByTokenHash(
		ctx,
		HashToken(rawToken),
	)
	if err != nil {
		return nil, err
	}

	if session.IsRevoked() {
		return nil, ErrSessionRevoked
	}

	if session.IsExpired() {
		return nil, ErrSessionExpired
	}

	return session, nil
}

func (s *Service) Touch(
	ctx context.Context,
	id uuid.UUID,
) error {
	return s.repository.UpdateLastUsed(ctx, id)
}

func (s *Service) Revoke(
	ctx context.Context,
	id uuid.UUID,
) error {
	if id == uuid.Nil {
		return ErrSessionNotFound
	}

	return s.repository.Revoke(ctx, id)
}

func (s *Service) RevokeAllForUser(
	ctx context.Context,
	userID uuid.UUID,
) error {
	if userID == uuid.Nil {
		return errors.New("user id is required")
	}

	return s.repository.RevokeAllForUser(ctx, userID)
}

func (s *Service) Cleanup(
	ctx context.Context,
) error {
	return s.repository.DeleteExpired(ctx)
}

func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func generateToken() (string, error) {
	buffer := make([]byte, TokenBytes)

	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}

	return hex.EncodeToString(buffer), nil
}

func normalizeIPAddress(value string) string {
	value = strings.TrimSpace(value)

	if value == "" {
		return ""
	}

	host, _, err := net.SplitHostPort(value)
	if err == nil {
		return host
	}

	if net.ParseIP(value) != nil {
		return value
	}

	return value
}
