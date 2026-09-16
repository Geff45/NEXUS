CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,

    user_id UUID NOT NULL,

    token_hash CHAR(64) NOT NULL UNIQUE,

    user_agent TEXT NOT NULL DEFAULT '',

    ip_address INET,

    expires_at TIMESTAMPTZ NOT NULL,

    revoked_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_sessions_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id
    ON sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON sessions(expires_at);

CREATE INDEX IF NOT EXISTS idx_sessions_revoked_at
    ON sessions(revoked_at);

CREATE INDEX IF NOT EXISTS idx_sessions_last_used_at
    ON sessions(last_used_at);