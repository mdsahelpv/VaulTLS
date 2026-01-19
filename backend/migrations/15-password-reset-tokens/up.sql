-- Add password reset tokens table
CREATE TABLE password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    used BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Add index on token_hash for fast lookups
CREATE INDEX idx_password_reset_tokens_token_hash ON password_reset_tokens(token_hash);

-- Add index on user_id for cleanup
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);

-- Add index on expires_at for cleanup queries
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);

-- Add composite index for efficient cleanup queries
CREATE INDEX idx_password_reset_tokens_user_expires ON password_reset_tokens(user_id, expires_at);
