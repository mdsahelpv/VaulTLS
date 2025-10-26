-- Up migration for certificate chain support
-- Add a column to store the full certificate chain as JSON
-- For self-signed CAs, this will contain just the single certificate
-- For imported CAs, this will contain the full chain including intermediate certificates
ALTER TABLE ca_certificates ADD COLUMN cert_chain TEXT;
