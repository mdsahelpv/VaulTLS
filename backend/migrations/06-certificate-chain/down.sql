-- Down migration for certificate chain support
ALTER TABLE ca_certificates DROP COLUMN cert_chain;
