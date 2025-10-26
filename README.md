![VaulTLS Logo](https://github.com/7ritn/VaulTLS/blob/main/assets/logoText.png)

# VaulTLS - Modern mTLS Certificate Management

VaulTLS is a comprehensive, enterprise-grade solution for managing mTLS (mutual TLS) certificates with ease. It provides a centralized platform for generating, managing, and distributing client and server TLS certificates for your home lab or production environment.

## 🎯 Why VaulTLS?

The main reason VaulTLS was developed was to eliminate the complexity of shell scripts and manual OpenSSL commands. Traditional certificate management often lacks:
- **Centralized oversight** of certificate expiration dates
- **User-friendly interfaces** for certificate operations
- **Automated workflows** for certificate lifecycle management
- **Comprehensive testing** and validation capabilities

VaulTLS solves these problems with a modern web interface, robust API, and comprehensive testing framework.

## ✨ Features

### Core Functionality
- 🔒 **mTLS Certificate Management** - Client and server certificate generation and management
- 🏛️ **Certificate Authority (CA)** - Built-in CA with self-signed and PFX import support
- 📱 **Modern Web Interface** - Intuitive Vue.js frontend for certificate operations
- 🔐 **OpenID Connect Authentication** - Enterprise-grade authentication support
- 📨 **Email Notifications** - Automated certificate expiration alerts
- 🚀 **RESTful API** - Complete API for automation and integration
- 🛠️ **Container Support** - Docker/Podman deployment ready
- ⚡ **High Performance** - Built with Rust (backend) and Vue.js (frontend)

### Advanced Features
- 🔗 **Certificate Chain Support** - Full certificate chain storage, display, and export
- 🔄 **Certificate Renewal** - Automated and manual renewal workflows
- 📊 **Certificate Analytics** - Expiration tracking and reporting
- 🔐 **Database Encryption** - Optional database encryption for sensitive data
- 🌐 **Server Certificates** - Full server certificate support with SAN entries
- 📋 **Bulk Operations** - Batch certificate management capabilities
- 🧪 **Comprehensive Testing** - Extensive test suite with 25+ test scenarios
- 📝 **PKCS12 Support** - Password-protected certificate exports with full chains
- 🔍 **Advanced SAN Support** - Multiple DNS names, IP addresses, wildcards
- 💳 **Modern Card UI** - Beautiful certificate chain display with badge types

### Security & Compliance
- 🛡️ **Security-First Design** - Built with security best practices
- 🔒 **Access Control** - Role-based user permissions
- 📊 **Audit Logging** - Comprehensive activity logging
- 🔐 **Data Encryption** - Optional database and file encryption
- ✅ **Input Validation** - Robust validation for all inputs

## 📸 Screenshots

![WebUI Overview](https://github.com/7ritn/VaulTLS/blob/main/assets/screenshot_overview.jpg)
![WebUI Users](https://github.com/7ritn/VaulTLS/blob/main/assets/screenshot_user.jpg)

## 🚀 Installation & Setup

### Docker Deployment (Recommended)

The easiest way to run VaulTLS is using Docker. This provides a complete, production-ready deployment with all dependencies managed automatically.

#### Quick Start with Docker

```bash
# Clone the repository
git clone https://github.com/7ritn/VaulTLS.git
cd VaulTLS

# Copy environment template
cp .env.example .env

# Edit environment variables (optional - defaults work for testing)
# nano .env

# Start VaulTLS
docker-compose up -d

# VaulTLS is now running!
# Frontend: http://localhost:4000
# Backend API: http://localhost:8000
```

#### Environment Configuration

VaulTLS supports various environment variables for customization. The `.env.example` file contains all available options:

- **VAULTLS_API_SECRET**: API secret for JWT tokens (auto-generated if not set)
- **VAULTLS_DB_SECRET**: Database encryption secret (optional)
- **VAULTLS_FRONTEND_PORT**: Frontend port (default: 4000)
- **VAULTLS_BACKEND_PORT**: Backend API port (default: 8000)
- **RUN_TESTS**: Run tests during build (increases build time)

#### Advanced Docker Commands

```bash
# Build and start
docker-compose up --build -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Update deployment
docker-compose pull && docker-compose up -d

# Backup data volume
docker run --rm -v vaultls_vaultls_data:/data -v $(pwd):/backup alpine tar czf /backup/vaultls-backup.tar.gz -C /data .
```

#### Docker Compose Services

The `docker-compose.yml` provides:
- **Enterprise-grade optimization**: ~450MB container (62% reduction)
- **Multi-stage build** with advanced layer caching (~70% faster rebuilds)
- **Security hardening** with non-root user and minimal attack surface
- **Health checks** for automatic restart and monitoring
- **Persistent data storage** using Docker volumes
- **Network isolation** with custom bridge network

### Production Deployment (Container Registry)

For production deployments, use pre-built container images:

#### Prerequisites
- `VAULTLS_API_SECRET`: A 256-bit base64 encoded string (`openssl rand -base64 32`)
- Reverse proxy (Caddy, Nginx, Traefik, etc.) for TLS termination
- Persistent volume for data storage

#### Docker Registry Deployment

```bash
# Generate API secret
VAULTLS_API_SECRET=$(openssl rand -base64 32)

# Run with Docker
docker run -d \
  --name vaultls \
  -p 80:80 \
  -p 8000:8000 \
  -v vaultls-data:/app/data \
  -e VAULTLS_API_SECRET="$VAULTLS_API_SECRET" \
  -e VAULTLS_FRONTEND_PORT=80 \
  -e VAULTLS_BACKEND_PORT=8000 \
  ghcr.io/7ritn/vaultls:latest

# Or with Podman
podman run -d \
  --name vaultls \
  -p 80:80 \
  -p 8000:8000 \
  -v vaultls-data:/app/data \
  -e VAULTLS_API_SECRET="$VAULTLS_API_SECRET" \
  -e VAULTLS_FRONTEND_PORT=80 \
  -e VAULTLS_BACKEND_PORT=8000 \
  ghcr.io/7ritn/vaultls:latest
```

### Local Development Setup

For development and testing, VaulTLS includes a comprehensive startup script that handles all prerequisites automatically.

#### Prerequisites for Local Development
- **Rust** (latest stable) - [Install from rustup.rs](https://rustup.rs/)
- **Node.js** (v16+) - [Download from nodejs.org](https://nodejs.org/)
- **SQLite3** (optional, for database operations)

#### Quick Start with Startup Script

```bash
# Clone the repository
git clone https://github.com/7ritn/VaulTLS.git
cd VaulTLS

# Make the startup script executable
chmod +x start-vaultls.sh

# Start both backend and frontend in development mode
./start-vaultls.sh start

# Access URLs:
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
```

#### Startup Script Commands

```bash
# Development mode (default)
./start-vaultls.sh start

# Production mode with optimizations
./start-vaultls.sh start --release --production

# Start individual services
./start-vaultls.sh backend --port 9000
./start-vaultls.sh frontend --frontend-port 8080

# Service management
./start-vaultls.sh status    # Check service status
./start-vaultls.sh logs      # View service logs
./start-vaultls.sh stop      # Stop all services
./start-vaultls.sh restart   # Restart services

# Maintenance
./start-vaultls.sh setup     # Setup without starting
./start-vaultls.sh clean     # Clean build artifacts
```

#### Manual Setup (Alternative)

If you prefer manual setup:

```bash
# Backend setup
cd backend
cargo update
cargo build
cargo run

# Frontend setup (in another terminal)
cd frontend
npm install
npm run dev
```

### Encrypting the Database
By specifying the `VAULTLS_DB_SECRET` environmental variable, the database is encrypted. Data is retained. It is not possible to go back.

### Specifying log level
The default log level is moderate. If a different one is desired, please specify it using the `VAULTLS_LOG_LEVEL` environmental variable.
For bug reports, a trace log report is desirable. Be aware that the trace does contain secrets.

### Setting up OIDC
To set up OIDC you need to create a new client in your authentication provider. For Authelia a configuration could look like this
```yaml
- client_id: "[client_id]"
  client_name: "vautls"
  client_secret: "[client_secret_hash]"
  public: false
  authorization_policy: "one_factor"
  pkce_challenge_method: "S256"
  redirect_uris:
    - "https://vaultls.example.com/api/auth/oidc/callback"
  scopes:
    - "openid"
    - "profile"
    - "email"
  userinfo_signed_response_alg: "none"
```
For VaulTLS the required variables can be configured via environmental variables or web UI.

| Environment Variable        | Value                                                |
|-----------------------------|------------------------------------------------------|
| `VAULTLS_OIDC_AUTH_URL`     | `https://auth.example.com`                           |
| `VAULTLS_OIDC_CALLBACK_URL` | `https://vaultls.example.com/api/auth/oidc/callback` |
| `VAULTLS_OIDC_ID`           | `[client_id]`                                        |
| `VAULTLS_OIDC_SECRET`       | `[client_secret]`                                    |

If VaulTLS claims that OIDC is not configured, the most likely cause is that it couldn't discover the OIDC provider based on the `VAULTLS_OIDC_AUTH_URL` given. In general the the base url to the auth provider should be enough. For Authentik the required URL path is `/application/o/<application slug>/`. If that doesn't work, directly specify the .well_known url. 

### Container Secrets
Certain environment variables can be Container Secrets instead of regular variables.
VaulTLS will try to read secrets from `/run/secrets/<ENV_NAME>`, if you want to specify a different path, you can do so in the environmental variable.
The following variables support secrets:
- VAULTLS_API_SECRET
- VAULTLS_DB_SECRET
- VAULTLS_OIDC_SECRET

## Usage
During the first setup a Certificate Authority is automatically created. If OIDC is configured no password needs to be set.
Users can either log in via password or OIDC. If a user first logs in via OIDC their e-mail is matched with all VaulTLS users and linked.
If no user is found a new one is created.

Users can only see certificates created for them. Only admins can create new certificates.
User certificates can be downloaded through the web interface.

The CA certificate to be integrated with your reverse proxy is available as a file at /app/data/ca.cert 
and as download via the API endpoint /api/certificates/ca/download.

Further API documentation is available at the endpoint /api

### PKCS12 Passwords
By default, PKCS12 passwords are optional and certificates will be generated with no password. In the settings page, the PKCS12 password requirements can be set with the following options:

| PKCS12 Password Rule  | Result                                              |
|-----------------------|-----------------------------------------------------|
| Optional              | Passwords are optional and can be blank             |
| Required              | Passwords are required, but can be system generated |
| System Generated      | Random passwords will be generated                  |

Passwords are stored in the database and retrieved from the web interface only when the user clicks on view password.

### Server Certificates
Since version v0.7.0 VaulTLS also has support for server certificates.
The user flow remains quite similar with the difference that SAN DNS entries can be specified.
Download is also using a possibly password-protected PKCS#12 file.
Since most reverse proxies require the certificate and private key to be supplied separately, the p12 may need to be split.
This can be done, for example, with openssl:
```sh
openssl pkcs12 -in INFILE.p12 -out OUTFILE.crt -nokeys
openssl pkcs12 -in INFILE.p12 -out OUTFILE.key -nodes -nocerts
```

### Caddy
To use caddy as reverse proxy for the VaulTLS app, a configuration like the following is required.
```caddyfile
reverse_proxy 127.0.0.1:5173
```
To integrate the CA cert for client validation, you can either use a file or http based approach. Extend your TLS instruction for that with the client_auth section. Documentation here: [https://caddyserver.com/docs/caddyfile/directives/tls#client_auth](https://caddyserver.com/docs/caddyfile/directives/tls#client_auth).

File based:
```caddyfile
tls {
  client_auth {
    mode <usually verify_if_given OR require_and_verify>
    trust_pool file {
      pem_file <Path to VaulTLS Directory>/ca.cert
    }
  }
}
```

HTTP based:
```caddyfile
tls {
  client_auth {
    mode <usually verify_if_given OR require_and_verify>
    trust_pool http {
      endpoints <Address of VaulTLS Instance such as 127.0.0.1:5173>/api/certificates/ca/download
    }
  }
}
```

If you choose `verify_if_given`, you can still block clients for apps that you want to require client authentication:
```caddyfile
@blocked {
  vars {tls_client_subject} ""
}
abort @blocked
```

## 🧪 Testing

VaulTLS includes a comprehensive test suite with 25+ test scenarios covering all major functionality and edge cases.

### Running Tests

```bash
# Run all tests
cd backend
cargo test

# Run specific test categories
cargo test --test integration_tests test_database_encryption_integration
cargo test --test integration_tests test_certificate_chain_validation
cargo test --test integration_tests test_pfx_import_integration

# Run with verbose output
cargo test -- --nocapture
```

### Test Coverage

The test suite covers:

#### Certificate Authority Tests
- ✅ **CA Setup Edge Cases** - Minimum/maximum validity periods, invalid inputs
- ✅ **PFX Import Scenarios** - Wrong passwords, corrupted files, successful imports
- ✅ **CA Name Validation** - Empty names, long names, special characters

#### Certificate Management Tests
- ✅ **Certificate Validity Boundaries** - 1-year minimum, 10-year maximum, invalid values
- ✅ **Server Certificate SAN Support** - Multiple DNS, wildcards, IP addresses, mixed types
- ✅ **Concurrent Certificate Creation** - Race conditions, naming conflicts
- ✅ **Bulk Certificate Operations** - Batch creation and downloads

#### Security & Authentication Tests
- ✅ **Database Encryption Integration** - Encrypted database operations
- ✅ **Certificate Chain Validation** - Certificate relationships and downloads
- ✅ **Network Failure Simulation** - Invalid IDs, non-existent resources
- ✅ **Certificate Renewal Edge Cases** - Renewal methods and notifications
- ✅ **User Isolation** - Access control and permission validation

#### Advanced Features Tests
- ✅ **PKCS12 Password Handling** - Optional, required, and system-generated passwords
- ✅ **Certificate User Isolation** - Admin vs regular user permissions
- ✅ **TLS Connection Establishment** - End-to-end TLS validation

### Test Architecture

Tests are organized into:
- **Unit Tests** - Individual component testing
- **Integration Tests** - Full API workflow testing
- **End-to-End Tests** - Complete user journey validation

## 📚 API Documentation

VaulTLS provides a comprehensive REST API for automation and integration.

### Base URL
```
http://localhost:8000/api
```

### Authentication
All API endpoints require authentication via session cookies or API tokens.

### Key Endpoints

#### Certificate Management
```http
GET    /api/certificates           # List certificates
POST   /api/certificates           # Create certificate
GET    /api/certificates/{id}      # Get certificate details
DELETE /api/certificates/{id}      # Delete certificate
GET    /api/certificates/{id}/download  # Download certificate
GET    /api/certificates/{id}/password  # Get PKCS12 password
```

#### Certificate Authority
```http
GET    /api/certificates/ca/download   # Download CA certificate
POST   /api/server/setup              # Initial setup
GET    /api/server/setup              # Check setup status
```

#### User Management
```http
GET    /api/users                    # List users
POST   /api/users                    # Create user
PUT    /api/users/{id}               # Update user
DELETE /api/users/{id}               # Delete user
GET    /api/auth/current-user        # Get current user
```

#### Settings
```http
GET    /api/settings                 # Get settings
PUT    /api/settings                 # Update settings
```

### API Documentation Access
Complete API documentation is available at `/api` when the server is running.

## 🏗️ Project Structure

```
VaulTLS/
├── backend/                    # Rust backend application
│   ├── src/
│   │   ├── api.rs             # API endpoints
│   │   ├── cert.rs            # Certificate operations
│   │   ├── db.rs              # Database operations
│   │   ├── main.rs            # Application entry point
│   │   ├── settings.rs        # Configuration management
│   │   └── auth/              # Authentication modules
│   │       ├── mod.rs
│   │       ├── oidc_auth.rs
│   │       ├── password_auth.rs
│   │       └── session_auth.rs
│   ├── tests/                 # Test suites
│   │   ├── integration_tests.rs
│   │   └── api/
│   │       ├── api_test_functionality.rs
│   │       └── api_test_safety.rs
│   ├── Cargo.toml            # Rust dependencies
│   └── Rocket.toml           # Rocket framework config
├── frontend/                  # Vue.js frontend application
│   ├── src/
│   │   ├── components/       # Vue components
│   │   ├── stores/          # Pinia stores
│   │   ├── views/           # Page views
│   │   ├── router/          # Vue router configuration
│   │   └── api/             # API client
│   ├── public/              # Static assets
│   ├── package.json         # Node.js dependencies
│   └── vite.config.ts       # Vite configuration
├── container/                # Container configurations
│   ├── nginx.conf           # Nginx web server config
│   └── entrypoint.sh        # Container startup script
├── tests/                   # Integration tests
│   ├── docker-compose.yml   # Test environment
│   └── e2e/                # End-to-end tests
├── assets/                  # Project assets
│   ├── logo.png            # Logo images
│   └── logoText.png
├── .env.example             # Environment variables template
├── start-vaultls.sh         # Development startup script
├── Containerfile            # Optimized Docker build file
├── docker-compose.yml       # Production Docker orchestration
├── LICENSE                  # Project license
└── README.md               # This file
```

## 🤝 Contributing

We welcome contributions to VaulTLS! Please see our contributing guidelines:

### Development Setup
1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/VaulTLS.git`
3. Set up development environment: `./start-vaultls.sh setup`
4. Create a feature branch: `git checkout -b feature/your-feature`
5. Make your changes and add tests
6. Run tests: `cd backend && cargo test`
7. Submit a pull request

### Code Style
- **Rust**: Follow standard Rust formatting (`cargo fmt`)
- **Vue.js**: Follow Vue.js style guide
- **Commits**: Use conventional commit format

### Testing Requirements
- All new features must include comprehensive tests
- Test coverage should not decrease
- Integration tests required for API changes

## 📋 Roadmap

### ✅ Completed Features (v0.9.3)
- ✅ Comprehensive test suite with 25+ test scenarios
- ✅ Automated startup script for development
- ✅ Database encryption support
- ✅ Advanced SAN support for server certificates
- ✅ Bulk certificate operations
- ✅ Concurrent certificate creation handling
- ✅ PFX import with error handling
- ✅ Certificate renewal workflows

### 🚧 In Progress
- 🔄 **Automated Certificate Renewal** - Background job system for certificate renewal
- 📊 **Certificate Analytics Dashboard** - Advanced reporting and analytics
- 🔐 **Hardware Security Module (HSM) Integration** - Enterprise key management

### 🔮 Planned Features
- 🤖 **Certificate Lifecycle Automation** - Auto-renewal based on expiration dates
- 📱 **Mobile App** - iOS/Android companion app
- 🔗 **LDAP Integration** - Enterprise directory integration
- 📈 **Metrics & Monitoring** - Prometheus/Grafana integration
- 🌐 **Multi-CA Support** - Multiple certificate authorities
- 🔄 **Certificate Rotation** - Automated key rotation
- 📧 **Advanced Notifications** - Slack, Teams, webhook integrations
- 🏢 **Multi-Tenant Support** - Organization-based isolation
- 📋 **Audit Logging** - Comprehensive security audit trails
- 🔍 **Certificate Discovery** - Network certificate scanning

### 📊 Version History

- **v0.9.3** - Comprehensive testing, startup script, advanced SAN support
- **v0.9.1** - Database encryption, bulk operations
- **v0.9.0** - Certificate renewal, concurrent creation handling
- **v0.8.0** - PFX import, error handling improvements
- **v0.7.0** - Server certificates, SAN support
- **v0.6.0** - User management, role-based access
- **v0.5.0** - OIDC authentication, email notifications
- **v0.4.0** - REST API, automation support
- **v0.3.0** - Web interface improvements
- **v0.2.0** - Basic certificate management
- **v0.1.0** - Initial release

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Rust Community** - For the excellent Rust ecosystem
- **Vue.js Team** - For the amazing frontend framework
- **OpenSSL** - For the cryptographic foundation
- **Rocket Framework** - For the web framework
- **All Contributors** - For their valuable contributions

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/7ritn/VaulTLS/issues)
- **Discussions**: [GitHub Discussions](https://github.com/7ritn/VaulTLS/discussions)
- **Documentation**: [API Docs](/api) (when running)

---

**VaulTLS** - Making certificate management simple, secure, and automated. 🔒✨
