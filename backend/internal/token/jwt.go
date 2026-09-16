package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"nexus/internal/users"
)

var ErrInvalidToken = errors.New("invalid token")

type Manager struct {
	secret     []byte
	issuer     string
	expiration time.Duration
}

type Claims struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
	Username  string
	Email     string
	IsCreator bool
	IsAdmin   bool
}

type JWTClaims struct {
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	IsCreator bool   `json:"is_creator"`
	IsAdmin   bool   `json:"is_admin"`

	jwt.RegisteredClaims
}

func NewManager(
	secret string,
	issuer string,
	expiration time.Duration,
) (*Manager, error) {
	if secret == "" {
		return nil, errors.New("JWT secret is required")
	}

	if len(secret) < 32 {
		return nil, errors.New("JWT secret must be at least 32 characters")
	}

	if issuer == "" {
		return nil, errors.New("JWT issuer is required")
	}

	if expiration <= 0 {
		return nil, errors.New("JWT expiration must be greater than zero")
	}

	return &Manager{
		secret:     []byte(secret),
		issuer:     issuer,
		expiration: expiration,
	}, nil
}

func (m *Manager) Generate(
	user *users.User,
	sessionID uuid.UUID,
) (string, error) {
	if user == nil {
		return "", errors.New("user is required")
	}

	if sessionID == uuid.Nil {
		return "", errors.New("session id is required")
	}

	now := time.Now()

	claims := JWTClaims{
		UserID:    user.ID.String(),
		SessionID: sessionID.String(),
		Username:  user.Username,
		Email:     user.Email,
		IsCreator: user.IsCreator,
		IsAdmin:   user.IsAdmin,

		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   user.ID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.expiration)),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}

	t := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	)

	signedToken, err := t.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signedToken, nil
}

func (m *Manager) Validate(
	tokenString string,
) (*Claims, error) {
	if tokenString == "" {
		return nil, ErrInvalidToken
	}

	token, err := jwt.ParseWithClaims(
		tokenString,
		&JWTClaims{},
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, ErrInvalidToken
			}

			return m.secret, nil
		},
		jwt.WithIssuer(m.issuer),
	)

	if err != nil {
		return nil, ErrInvalidToken
	}

	jwtClaims, ok := token.Claims.(*JWTClaims)

	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	userID, err := uuid.Parse(jwtClaims.UserID)
	if err != nil {
		return nil, ErrInvalidToken
	}

	sessionID, err := uuid.Parse(jwtClaims.SessionID)
	if err != nil {
		return nil, ErrInvalidToken
	}

	return &Claims{
		UserID:    userID,
		SessionID: sessionID,
		Username:  jwtClaims.Username,
		Email:     jwtClaims.Email,
		IsCreator: jwtClaims.IsCreator,
		IsAdmin:   jwtClaims.IsAdmin,
	}, nil
}
