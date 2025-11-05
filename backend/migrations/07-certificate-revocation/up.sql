-- Up migration for certificate revocation support
-- Add certificate_revocation table to track revoked certificates
CREATE TABLE certificate_revocation (
    id INTEGER PRIMARY KEY,
    certificate_id INTEGER NOT NULL,
    revocation_date INTEGER NOT NULL,
    revocation_reason INTEGER NOT NULL, -- 0=unspecified, 1=keyCompromise, 2=caCompromise, 3=affiliationChanged, 4=superseded, 5=cessationOfOperation, 6=certificateHold, 8=removeFromCRL, 9=privilegeWithdrawn, 10=aaCompromise
    revoked_by_user_id INTEGER,
    FOREIGN KEY(certificate_id) REFERENCES user_certificates(id) ON DELETE CASCADE,
    FOREIGN KEY(revoked_by_user_id) REFERENCES users(id)
);

-- Create index for efficient revocation status lookups
CREATE INDEX idx_certificate_revocation_certificate_id ON certificate_revocation(certificate_id);
CREATE INDEX idx_certificate_revocation_revocation_date ON certificate_revocation(revocation_date);
