-- Create table for tracking failed login attempts for account lockout protection
CREATE TABLE failed_login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,  -- NULL for attempts by non-existent users
    ip_address TEXT NOT NULL,
    attempted_at INTEGER NOT NULL,  -- Unix timestamp in milliseconds
    user_agent TEXT,  -- Browser/client user agent string
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create index for efficient queries by user_id
CREATE INDEX idx_failed_login_attempts_user_id ON failed_login_attempts(user_id);

-- Create index for efficient queries by IP address
CREATE INDEX idx_failed_login_attempts_ip_address ON failed_login_attempts(ip_address);

-- Create index for efficient cleanup of old attempts
CREATE INDEX idx_failed_login_attempts_attempted_at ON failed_login_attempts(attempted_at);

-- Create composite index for account lockout queries (user_id + time window)
CREATE INDEX idx_failed_login_attempts_user_time ON failed_login_attempts(user_id, attempted_at);

-- Create composite index for IP-based lockout queries (ip_address + time window)
CREATE INDEX idx_failed_login_attempts_ip_time ON failed_login_attempts(ip_address, attempted_at);
