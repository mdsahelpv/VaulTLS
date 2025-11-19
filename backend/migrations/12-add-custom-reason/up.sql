-- Add custom_reason column to certificate_revocation table
ALTER TABLE certificate_revocation ADD COLUMN custom_reason TEXT;
