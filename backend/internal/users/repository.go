package users

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUserNotFound   = errors.New("user not found")
	ErrUsernameExists = errors.New("username already exists")
	ErrEmailExists    = errors.New("email already exists")
)

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
	user *User,
) error {
	query := `
INSERT INTO users (
username,
email,
password_hash,
status,
email_verified,
phone_verified,
is_creator,
is_admin
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, created_at, updated_at
`

	err := r.pool.QueryRow(
		ctx,
		query,
		user.Username,
		user.Email,
		user.PasswordHash,
		user.Status,
		user.EmailVerified,
		user.PhoneVerified,
		user.IsCreator,
		user.IsAdmin,
	).Scan(
		&user.ID,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	return nil
}

func (r *PostgresRepository) FindByID(
	ctx context.Context,
	id uuid.UUID,
) (*User, error) {
	query := `
SELECT
id,
username,
email,
password_hash,
status,
email_verified,
phone_verified,
is_creator,
is_admin,
created_at,
updated_at,
last_login_at
FROM users
WHERE id = $1
`

	user := &User{}

	err := r.pool.QueryRow(
		ctx,
		query,
		id,
	).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Status,
		&user.EmailVerified,
		&user.PhoneVerified,
		&user.IsCreator,
		&user.IsAdmin,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("find user by id: %w", err)
	}

	return user, nil
}

func (r *PostgresRepository) FindByUsername(
	ctx context.Context,
	username string,
) (*User, error) {
	query := `
SELECT
id,
username,
email,
password_hash,
status,
email_verified,
phone_verified,
is_creator,
is_admin,
created_at,
updated_at,
last_login_at
FROM users
WHERE username = $1
`

	user := &User{}

	err := r.pool.QueryRow(
		ctx,
		query,
		username,
	).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Status,
		&user.EmailVerified,
		&user.PhoneVerified,
		&user.IsCreator,
		&user.IsAdmin,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("find user by username: %w", err)
	}

	return user, nil
}

func (r *PostgresRepository) FindByEmail(
	ctx context.Context,
	email string,
) (*User, error) {
	query := `
SELECT
id,
username,
email,
password_hash,
status,
email_verified,
phone_verified,
is_creator,
is_admin,
created_at,
updated_at,
last_login_at
FROM users
WHERE email = $1
`

	user := &User{}

	err := r.pool.QueryRow(
		ctx,
		query,
		email,
	).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Status,
		&user.EmailVerified,
		&user.PhoneVerified,
		&user.IsCreator,
		&user.IsAdmin,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLoginAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUserNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("find user by email: %w", err)
	}

	return user, nil
}

func (r *PostgresRepository) UpdateLastLogin(
	ctx context.Context,
	id uuid.UUID,
) error {
	query := `
UPDATE users
SET
last_login_at = NOW(),
updated_at = NOW()
WHERE id = $1
`

	result, err := r.pool.Exec(
		ctx,
		query,
		id,
	)

	if err != nil {
		return fmt.Errorf("update last login: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (r *PostgresRepository) UpdatePassword(
	ctx context.Context,
	id uuid.UUID,
	passwordHash string,
) error {
	query := `
UPDATE users
SET
password_hash = $1,
updated_at = NOW()
WHERE id = $2
`

	result, err := r.pool.Exec(
		ctx,
		query,
		passwordHash,
		id,
	)

	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrUserNotFound
	}

	return nil
}
