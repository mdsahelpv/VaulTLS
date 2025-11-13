-- Remove is_revoked column from user_certificates table
-- This reverts to the previous behavior where revocation status is determined by the certificate_revocation table

-- Drop the index first
DROP INDEX IF EXISTS idx_user_certificates_is_revoked;

-- Remove the is_revoked column
-- Note: SQLite doesn't support DROP COLUMN directly, so we need to recreate the table
CREATE TABLE user_certificates_temp (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    created_on INTEGER NOT NULL,
    valid_until INTEGER NOT NULL,
    pkcs12 BLOB NOT NULL,
    pkcs12_password TEXT,
    user_id INTEGER NOT NULL,
    type INTEGER NOT NULL,
    renew_method INTEGER NOT NULL,
    ca_id INTEGER NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(ca_id) REFERENCES ca_certificates(id)
);

-- Copy all data except is_revoked column
INSERT INTO user_certificates_temp
SELECT id, name, created_on, valid_until, pkcs12, pkcs12_password, user_id, type, renew_method, ca_id
FROM user_certificates;

-- Drop the old table
DROP TABLE user_certificates;

-- Rename the temporary table
ALTER TABLE user_certificates_temp RENAME TO user_certificates;

-- Recreate indexes
CREATE INDEX idx_user_certificates_user_id ON user_certificates(user_id);
CREATE INDEX idx_user_certificates_ca_id ON user_certificates(ca_id);
