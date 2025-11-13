-- Fix certificate revocation foreign key constraint
-- Remove ON DELETE CASCADE to preserve revocation history when certificates are deleted

-- SQLite doesn't support DROP CONSTRAINT directly, so we need to recreate the table
-- First, create a temporary table with the correct structure
CREATE TABLE certificate_revocation_temp (
    id INTEGER PRIMARY KEY,
    certificate_id INTEGER NOT NULL,
    revocation_date INTEGER NOT NULL,
    revocation_reason INTEGER NOT NULL,
    revoked_by_user_id INTEGER,
    FOREIGN KEY(certificate_id) REFERENCES user_certificates(id), -- Removed ON DELETE CASCADE
    FOREIGN KEY(revoked_by_user_id) REFERENCES users(id)
);

-- Copy all data from the old table to the new table
INSERT INTO certificate_revocation_temp
SELECT id, certificate_id, revocation_date, revocation_reason, revoked_by_user_id
FROM certificate_revocation;

-- Drop the old table
DROP TABLE certificate_revocation;

-- Rename the temporary table to the original name
ALTER TABLE certificate_revocation_temp RENAME TO certificate_revocation;

-- Recreate the indexes
CREATE INDEX idx_certificate_revocation_certificate_id ON certificate_revocation(certificate_id);
CREATE INDEX idx_certificate_revocation_revocation_date ON certificate_revocation(revocation_date);
