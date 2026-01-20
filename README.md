# VaulTLS - Production-Ready mTLS Certificate Management

VaulTLS is a robust, lightweight solution for managing Mutual TLS (mTLS) certificates in production environments. It provides a centralized platform for generating, managing, and distributing client and server certificates with enterprise-grade security, reliability, and scalability.

## 🚀 Key Features

### Security & Reliability
- 🔒 **Certificate Authority**: Built-in CA with support for self-signed roots and PFX/P12 imports
- 🛡️ **Production Security**: File locking, memory limits, input validation, and DoS protection
- 🔐 **Authentication**: Secure login with local password and OpenID Connect (OIDC) support
- 🚫 **Revocation Management**: Integrated CRL distribution and OCSP responder
- 📊 **Comprehensive Audit**: Detailed logging with configurable retention policies
- 🔄 **State Synchronization**: Real-time frontend/backend sync with periodic updates
- 🚪 **Concurrent Safety**: File locking prevents data corruption in multi-process environments

### User Experience
- 📱 **Modern Web UI**: Intuitive Vue.js 3 frontend for easy management
- 📨 **Notifications**: Email alerts for certificate expiry and system events
- 🎯 **Dual CA Modes**: Root CA mode (subordinate CA issuance) and Regular CA mode (all certificate types)
- 🛠️ **Developer Friendly**: RESTful API with OpenAPI documentation

### Deployment & Operations
- 📦 **Container Ready**: Optimized Docker images for easy deployment
- ⚙️ **Flexible Configuration**: Comprehensive settings via JSON configuration
- 🔧 **Service Architecture**: Clean separation of concerns with service layer
- 📈 **Monitoring Ready**: Structured logging and audit trails for compliance

## 🏗️ Architecture

- **Backend**: Rust (Rocket framework, OpenSSL, SQLite)
- **Frontend**: Vue.js 3 + TypeScript (Vite, Pinia, Bootstrap)
- **Database**: SQLite3 (with optional folder-level or database-level encryption)

## 🛠️ Quick Start

### Docker (Recommended)

1. Clone the repository:
   ```bash
   git clone https://git.yawal.io/mdsahelpv/vaultls.git
   cd VaulTLS
   ```

2. Setup environment:
   ```bash
   cp .env.example .env
   # Edit .env to set your secrets
   ```

3. Build and Start with Docker Compose:
   ```bash
   docker compose up --build -d
   ```

Access **VaulTLS GUI** at `http://localhost:4000` and the **API** at `http://localhost:8000`.

---

### Local Development

1. **Prerequisites**: Rust (latest stable), Node.js (v18+), and SQLite3.
2. **Setup and Start**:
   ```bash
   ./start-vaultls.sh start
   ```
   This script handles dependencies, builds both components, and starts the services.

## ⚙️ Configuration

VaulTLS supports flexible configuration through multiple methods:

### Environment Variables (.env)
Basic deployment configuration:

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULTLS_API_SECRET` | Secret for JWT & session tokens | Auto-generated |
| `VAULTLS_DB_SECRET` | Database encryption secret | - |
| `VAULTLS_FRONTEND_PORT` | External frontend port (Docker) | 4000 |
| `VAULTLS_BACKEND_PORT` | External backend port (Docker) | 8000 |
| `VAULTLS_LOG_LEVEL` | Logging level (trace, debug, info, warn, error) | info |
| `ROCKET_PORT` | Backend API port | 3737 |
| `RUN_TESTS` | Run tests during build | false |

### Application Settings (settings.json)
Comprehensive configuration for security, performance, and features:

```json
{
  "common": {
    "password_enabled": true,
    "vaultls_url": "https://vaultls.example.com",
    "is_root_ca": false,
    "file_size_limits": {
      "max_pfx_size_mb": 10,
      "max_csr_size_mb": 1,
      "max_cert_download_size_mb": 5,
      "max_cert_chain_size": 100,
      "max_cert_size_mb": 50
    }
  },
  "audit": {
    "enabled": true,
    "retention_days": 365,
    "log_authentication": true,
    "log_certificate_operations": true
  }
}
```

**Key Security Settings:**
- **File Size Limits**: Prevent DoS attacks with configurable upload/download limits
- **Memory Protection**: Certificate chain size limits and oversized file handling
- **Audit Configuration**: Comprehensive logging with retention policies
- **CA Mode**: Choose between Root CA (subordinate CA only) or Regular CA (all certificates)

📖 **Complete Configuration Guide**: See [`SETTINGS.md`](SETTINGS.md) and [`settings.example.json`](settings.example.json) for detailed documentation of all configuration options.

### 🌐 Multi-CA CRL & OCSP Deployment

VaulTLS supports hosting multiple CAs with distinct revocation endpoints:

| Service | Endpoint URL | Configuration Note |
|:---|:---|:---|
| **CRL (Specific CA)** | `/api/certificates/crl/<ca_id>` | Set `cdp_url` to this path when creating a CA. |
| **CRL (Default CA)** | `/api/certificates/crl` | Points to the most recently created or default CA. |
| **OCSP Responder** | `/api/ocsp` | Unified endpoint. Set `aia_url` to this path for **all** CAs. |

## 📖 Usage

### Initial Setup
1. **Choose CA Mode**: Select between Root CA mode (subordinate CA issuance only) or Regular CA mode (all certificate types)
2. **Create Root CA**: Generate a self-signed root CA or import an existing PFX/P12 file
3. **Administrator Account**: Create the first administrator account with secure password policies

### Certificate Management
1. **Issue Certificates**: Use the "Create Certificate" wizard for CSR signing or full certificate generation
2. **CSR Signing**: Upload and sign Certificate Signing Requests with comprehensive validation
3. **Subject Alternative Names**: Support for DNS names, IP addresses, and email addresses
4. **Security Validation**: Automatic key strength checking and extension validation

### Revocation & Compliance
1. **One-Click Revocation**: Simple certificate revocation with RFC 5280 compliance
2. **CRL Distribution**: Automatic CRL generation and distribution
3. **OCSP Responder**: Real-time certificate status checking
4. **Audit Trail**: Complete audit logging of all certificate operations

### API Integration
- **RESTful API**: Full programmatic access to all features
- **OpenAPI Documentation**: Interactive API documentation at `/api/openapi.json`
- **Rate Limiting**: Built-in protection against abuse
- **Authentication**: JWT-based secure API access

## 🛡️ Security Features

### Production-Ready Security
- **File Locking**: Prevents data corruption in concurrent access scenarios
- **Memory Limits**: Configurable file size limits prevent DoS attacks
- **Input Validation**: Comprehensive validation of all user inputs
- **Secure Defaults**: Conservative security settings out of the box
- **Audit Logging**: Complete audit trail with configurable retention

### Authentication & Authorization
- **Multi-Factor Ready**: OIDC integration support
- **Role-Based Access**: Admin and user roles with appropriate permissions
- **Session Management**: Secure JWT tokens with configurable expiration
- **Password Security**: Server-side hashing with configurable policies

### Compliance & Monitoring
- **RFC 5280 Compliance**: Standards-compliant certificate operations
- **Structured Logging**: Machine-readable logs for monitoring systems
- **Configurable Retention**: Audit log retention policies for compliance
- **Certificate Lifecycle**: Automated expiry notifications and tracking

## 📋 Deployment Readiness

VaulTLS has undergone extensive hardening for production deployment:

✅ **Security Hardening**: File locking, memory limits, input validation
✅ **Concurrent Safety**: Protected against multi-process corruption
✅ **Error Handling**: Comprehensive error handling without panics
✅ **State Synchronization**: Real-time frontend/backend consistency
✅ **Configuration Management**: Flexible JSON-based configuration
✅ **Audit & Compliance**: Complete audit trails and retention policies

📖 **Deployment Guide**: See [`DEPLOYMENT_READINESS_ASSESSMENT.md`](DEPLOYMENT_READINESS_ASSESSMENT.md) for detailed production readiness information.

## 📊 Development Status

VaulTLS is currently in **Phase 2** of development with production-ready security features:

### ✅ Phase 1 Complete: Critical Security Fixes
- Authentication system hardening
- Input validation and sanitization
- Race condition fixes with database transactions
- Comprehensive error handling

### ✅ Phase 2 Complete: Reliability Improvements
- File locking for concurrent access safety
- Memory limits and DoS protection
- State synchronization between frontend/backend
- Service layer architecture refactoring

### 🔄 Phase 3: Quality Improvements (Ongoing)
- Unit and integration test coverage
- Performance optimization
- Enhanced monitoring and metrics
- Advanced deployment configurations

📋 **Current Task Status**: See [`tasklist.md`](tasklist.md) for detailed progress on all development tasks.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes with comprehensive tests
4. Ensure all existing tests pass
5. Submit a pull request with detailed description

### Coding Standards
- **Rust**: Follow standard Rust idioms and error handling patterns
- **TypeScript/Vue**: Use TypeScript strictly with proper type annotations
- **Security**: All changes must maintain or improve security posture
- **Testing**: Include tests for new features and bug fixes

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
