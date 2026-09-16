package sessions

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  string
	UserAgent  string
	IPAddress  string
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
	LastUsedAt time.Time
}

func (s *Session) IsRevoked() bool {
	return s.RevokedAt != nil
}

func (s *Session) IsExpired() bool {
	return !time.Now().Before(s.ExpiresAt)
}

func (s *Session) IsValid() bool {
	return !s.IsRevoked() && !s.IsExpired()
}
