ALTER TABLE ca_certificates ADD COLUMN can_create_subordinate_ca BOOLEAN NOT NULL DEFAULT 0;
