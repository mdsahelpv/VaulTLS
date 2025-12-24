# VaulTLS - Modern mTLS Certificate Management

VaulTLS is a robust, lightweight solution for managing Mutual TLS (mTLS) certificates. It provides a centralized platform for generating, managing, and distributing client and server certificates with a focus on simplicity and security.

## 🚀 Key Features

- 🔒 **Certificate Authority**: Built-in CA with support for self-signed roots and PFX/P12 imports.
- 📱 **Modern Web UI**: Intuitive Vue.js 3 frontend for easy management.
- 🔐 **Authentication**: Secure login with local password and OpenID Connect (OIDC) support.
- 🚫 **Revocation Management**: Integrated CRL distribution and OCSP responder.
- 📊 **Audit Logging**: Comprehensive tracking of all administrative and certificate actions.
- 📨 **Notifications**: Email alerts for certificate expiry and system events.
- 🛠️ **Developer Friendly**: RESTful API with OpenAPI documentation.
- 📦 **Container Ready**: Optimized Docker images for easy deployment.

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

3. Start with Docker Compose:
   ```bash
   docker-compose up -d
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

Key environment variables available in `.env`:

| Variable | Description | Default |
|----------|-------------|---------|
| `VAULTLS_API_SECRET` | Secret for JWT & session tokens | Auto-generated |
| `VAULTLS_DB_SECRET` | Database encryption secret | - |
| `HTTP_PORT` | External frontend port (Docker) | 80 |
| `BACKEND_API_PORT` | External backend port (Docker) | 8000 |
| `RUN_TESTS` | Run tests during build | false |

## 📖 Usage

1. **Initial Setup**: On first access, you'll be prompted to create the root CA and the first administrator account.
2. **Issue Certificates**: Use the "Create Certificate" wizard for CSR signing or full generation.
3. **Revocation**: Simple one-click revocation with automatic CRL/OCSP updates.
4. **API**: Explore the API via the built-in documentation at `/api/openapi.json`.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
