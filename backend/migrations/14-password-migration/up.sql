-- Migration: Remove insecure V2 password hashes
-- This migration invalidates all V2 (double-hashed) passwords for security reasons.
-- Users with V2 hashes will need to reset their passwords.
UPDATE users SET password_hash = NULL WHERE password_hash LIKE 'v2%';
