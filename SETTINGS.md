# VaulTLS Settings Configuration

This document describes all available configuration options in VaulTLS.

## Configuration File

Settings are stored in `settings.json` in the application root directory. The application loads these settings on startup.

## Configuration Sections

### Common Settings (`common`)

Basic application settings.

```json
{
  "common": {
    "password_enabled": true,
    "vaultls_url": "https://vaultls.example.com",
    "password_rule": 0,
    "is_root_ca": false,
    "file_size_limits": {
      "max_pfx_size_mb": 10,
      "max_csr_size_mb": 1,
      "max_cert_download_size_mb": 5,
      "max_cert_chain_size": 100,
      "max_cert_size_mb": 50
    }
  }
}
```

**Options:**
- `password_enabled`: Enable/disable password-based authentication (boolean)
- `vaultls_url`: Base URL of the VaulTLS application (string)
- `password_rule`: Password complexity rule (0=any, 1=required, 2=system-generated)
- `is_root_ca`: Whether this instance operates as a Root CA (boolean)
- `file_size_limits`: File size restrictions for security

**File Size Limits:**
- `max_pfx_size_mb`: Maximum PFX file size for CA imports/setup (default: 10 MB)
- `max_csr_size_mb`: Maximum CSR file size for certificate signing (default: 1 MB)
- `max_cert_download_size_mb`: Maximum certificate download response size (default: 5 MB)
- `max_cert_chain_size`: Maximum certificates in a certificate chain (default: 100)
- `max_cert_size_mb`: Maximum size of individual certificates (default: 50 MB)

### Authentication Settings (`auth`)

JWT authentication configuration.

```json
{
  "auth": {
    "jwt_key": "auto-generated-jwt-secret-key"
  }
}
```

**Options:**
- `jwt_key`: Secret key for JWT token signing (auto-generated if not provided)

### OIDC Settings (`oidc`)

OpenID Connect authentication configuration.

```json
{
  "oidc": {
    "id": "your-oidc-client-id",
    "secret": "your-oidc-client-secret",
    "auth_url": "https://your-oidc-provider.com",
    "callback_url": "https://vaultls.example.com/api/auth/oidc/callback"
  }
}
```

**Options:**
- `id`: OIDC client ID
- `secret`: OIDC client secret
- `auth_url`: OIDC provider authorization URL
- `callback_url`: OIDC callback URL for this application

### Mail Settings (`mail`)

Email notification configuration.

```json
{
  "mail": {
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "encryption": 1,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "from": "noreply@vaultls.example.com"
  }
}
```

**Options:**
- `smtp_host`: SMTP server hostname
- `smtp_port`: SMTP server port
- `encryption`: Encryption type (0=None, 1=STARTTLS, 2=SSL/TLS)
- `username`: SMTP authentication username
- `password`: SMTP authentication password
- `from`: Sender email address for notifications

### CRL Settings (`crl`)

Certificate Revocation List configuration.

```json
{
  "crl": {
    "validity_days": 7,
    "refresh_interval_hours": 24,
    "distribution_url": "https://vaultls.example.com/api/certificates/crl",
    "enabled": true
  }
}
```

**Options:**
- `validity_days`: How long CRL is valid (default: 7 days)
- `refresh_interval_hours`: How often to refresh CRL cache (default: 24 hours)
- `distribution_url`: URL where CRL is distributed (optional)
- `enabled`: Whether CRL generation is enabled (default: true)

### OCSP Settings (`ocsp`)

Online Certificate Status Protocol configuration.

```json
{
  "ocsp": {
    "responder_url": "https://vaultls.example.com/api/ocsp",
    "validity_hours": 24,
    "signing_cert_path": null,
    "enabled": true
  }
}
```

**Options:**
- `responder_url`: OCSP responder URL (optional, auto-generated if not set)
- `validity_hours`: How long OCSP responses are valid (default: 24 hours)
- `signing_cert_path`: Path to OCSP signing certificate (optional)
- `enabled`: Whether OCSP is enabled (default: true)

### Audit Settings (`audit`)

Audit logging configuration.

```json
{
  "audit": {
    "enabled": true,
    "retention_days": 365,
    "log_authentication": true,
    "log_certificate_operations": true,
    "log_ca_operations": true,
    "log_user_operations": true,
    "log_settings_changes": true,
    "log_system_events": true,
    "max_log_size_mb": 100
  }
}
```

**Options:**
- `enabled`: Whether audit logging is enabled (default: true)
- `retention_days`: How long to keep audit logs (default: 365 days)
- `log_authentication`: Log authentication events (default: true)
- `log_certificate_operations`: Log certificate CRUD operations (default: true)
- `log_ca_operations`: Log CA operations (default: true)
- `log_user_operations`: Log user management operations (default: true)
- `log_settings_changes`: Log settings changes (default: true)
- `log_system_events`: Log system events (default: true)
- `max_log_size_mb`: Maximum audit log file size before rotation (default: 100 MB)

### Logic Settings (`logic`)

Internal application logic settings.

```json
{
  "logic": {
    "db_encrypted": false
  }
}
```

**Options:**
- `db_encrypted`: Whether the database is encrypted (internal use)

## Configuration Methods

### 1. Direct File Edit
Edit `settings.json` directly and restart the application.

### 2. API Update (Admin Only)
Use the `/api/settings` endpoint to update settings at runtime:

```bash
curl -X PUT -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  http://localhost:3737/api/settings \
  -d '{"common": {"file_size_limits": {"max_pfx_size_mb": 20}}}'
```

### 3. Environment Variables
Some settings can be overridden with environment variables:
- `VAULTLS_PASSWORD_ENABLED`
- `VAULTLS_URL`
- `VAULTLS_LOG_LEVEL`
- `ROCKET_PORT`

## Default Values

All settings have sensible defaults. If `settings.json` doesn't exist or is incomplete, the application will use default values and create/update the file automatically.

## Security Notes

- Keep `auth.jwt_key` and OIDC secrets secure
- File size limits prevent DoS attacks
- Audit logging should be enabled in production
- Use HTTPS URLs for `vaultls_url` in production
