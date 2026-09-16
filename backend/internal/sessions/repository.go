package sessions

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionRevoked  = errors.New("session revoked")
	ErrSessionExpired  = errors.New("session expired")
)

type Repository interface {
	Create(ctx context.Context, session *Session) error
	FindByID(ctx context.Context, id uuid.UUID) (*Session, error)
	FindByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	Revoke(ctx context.Context, id uuid.UUID) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
	UpdateLastUsed(ctx context.Context, id uuid.UUID) error
	DeleteExpired(ctx context.Context) error
}

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{
		pool: pool,
	}
}

func (r *PostgresRepository) Create(
	ctx context.Context,
	session *Session,
) error {
	query := `
INSERT INTO sessions (
id,
user_id,
token_hash,
user_agent,
ip_address,
expires_at,
created_at,
last_used_at
)
VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
RETURNING created_at, last_used_at
`

	err := r.pool.QueryRow(
		ctx,
		query,
		session.ID,
		session.UserID,
		session.TokenHash,
		session.UserAgent,
		session.IPAddress,
		session.ExpiresAt,
	).Scan(
		&session.CreatedAt,
		&session.LastUsedAt,
	)

	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	return nil
}

func (r *PostgresRepository) FindByID(
	ctx context.Context,
	id uuid.UUID,
) (*Session, error) {
	query := `
SELECT
id,
user_id,
token_hash,
user_agent,
COALESCE(host(ip_address), ''),
expires_at,
revoked_at,
created_at,
last_used_at
FROM sessions
WHERE id = $1
`

	session := &Session{}

	err := r.pool.QueryRow(
		ctx,
		query,
		id,
	).Scan(
		&session.ID,
		&session.UserID,
		&session.TokenHash,
		&session.UserAgent,
		&session.IPAddress,
		&session.ExpiresAt,
		&session.RevokedAt,
		&session.CreatedAt,
		&session.LastUsedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("find session by id: %w", err)
	}

	return session, nil
}

func (r *PostgresRepository) FindByTokenHash(
	ctx context.Context,
	tokenHash string,
) (*Session, error) {
	query := `
SELECT
id,
user_id,
token_hash,
user_agent,
COALESCE(host(ip_address), ''),
expires_at,
revoked_at,
created_at,
last_used_at
FROM sessions
WHERE token_hash = $1
`

	session := &Session{}

	err := r.pool.QueryRow(
		ctx,
		query,
		tokenHash,
	).Scan(
		&session.ID,
		&session.UserID,
		&session.TokenHash,
		&session.UserAgent,
		&session.IPAddress,
		&session.ExpiresAt,
		&session.RevokedAt,
		&session.CreatedAt,
		&session.LastUsedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("find session by token hash: %w", err)
	}

	return session, nil
}

func (r *PostgresRepository) Revoke(
	ctx context.Context,
	id uuid.UUID,
) error {
	query := `
UPDATE sessions
SET revoked_at = COALESCE(revoked_at, NOW())
WHERE id = $1
`

	result, err := r.pool.Exec(
		ctx,
		query,
		id,
	)

	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrSessionNotFound
	}

	return nil
}

func (r *PostgresRepository) RevokeAllForUser(
	ctx context.Context,
	userID uuid.UUID,
) error {
	query := `
UPDATE sessions
SET revoked_at = COALESCE(revoked_at, NOW())
WHERE user_id = $1
  AND revoked_at IS NULL
`

	_, err := r.pool.Exec(
		ctx,
		query,
		userID,
	)

	if err != nil {
		return fmt.Errorf("revoke all user sessions: %w", err)
	}

	return nil
}

func (r *PostgresRepository) UpdateLastUsed(
	ctx context.Context,
	id uuid.UUID,
) error {
	query := `
UPDATE sessions
SET last_used_at = NOW()
WHERE id = $1
  AND revoked_at IS NULL
  AND expires_at > NOW()
`

	result, err := r.pool.Exec(
		ctx,
		query,
		id,
	)

	if err != nil {
		return fmt.Errorf("update session last used: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrSessionNotFound
	}

	return nil
}

func (r *PostgresRepository) DeleteExpired(
	ctx context.Context,
) error {
	query := `
DELETE FROM sessions
WHERE expires_at <= NOW()
   OR revoked_at IS NOT NULL
`

	_, err := r.pool.Exec(ctx, query)

	if err != nil {
		return fmt.Errorf("delete expired sessions: %w", err)
	}

	return nil
}
