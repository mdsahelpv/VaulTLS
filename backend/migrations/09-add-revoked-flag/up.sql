-- Add is_revoked column to user_certificates table
-- This ensures revocation status persists even when revocation history is cleared

-- Add the is_revoked column with default value 0 (not revoked)
ALTER TABLE user_certificates ADD COLUMN is_revoked INTEGER NOT NULL DEFAULT 0;

-- Update existing revoked certificates based on certificate_revocation table
UPDATE user_certificates
SET is_revoked = 1
WHERE id IN (
    SELECT DISTINCT certificate_id
    FROM certificate_revocation
);

-- Create index for efficient revoked certificate queries
CREATE INDEX idx_user_certificates_is_revoked ON user_certificates(is_revoked);
