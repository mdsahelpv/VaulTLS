# VaulTLS - mTLS Certificate Management

A production-ready solution for managing Mutual TLS (mTLS) certificates with enterprise-grade security and scalability.

## 📸 Screenshots

### Certificate Overview Dashboard
![VaulTLS Certificate Overview](assets/ss1.jpg)

### User Management Interface
![VaulTLS User Interface](assets/ss2.jpg)

## 🚀 Key Features

- 🔒 **Certificate Authority**: Self-signed root CA or PFX import
- 📱 **Modern Web UI**: Vue.js 3 frontend for easy certificate management
- 🛡️ **Security First**: File locking, input validation, audit logging
- 🚫 **Revocation**: CRL distribution and OCSP responder
- 🔐 **Authentication**: Password + OIDC support
- 📦 **Container Ready**: Optimized Docker deployment

## 🛠️ Quick Start

### Docker (Recommended)

```bash
git clone https://git.yawal.io/mdsahelpv/vaultls.git
cd VaulTLS
cp .env.example .env
# Edit .env file with your secrets
docker compose up --build -d
```

Access at `http://localhost:4000`

### Local Development

```bash
# Prerequisites: Rust, Node.js v18+, SQLite3
./start-vaultls.sh start
```

## 📖 Usage

1. **Setup**: Choose CA mode and create/import your root CA
2. **Create Certificates**: Generate client/server certificates or sign CSRs
3. **Manage**: Revoke certificates, view audit logs, configure settings

## ⚙️ Configuration

- **Environment**: `.env` file for basic settings
- **Application**: `settings.json` for advanced configuration
- **Documentation**: See [`SETTINGS.md`](SETTINGS.md) for details

## 🔗 Multi-CA Support

| Service | URL Pattern | Notes |
|:---|:---|:---|
| CRL | `/api/certificates/crl/<ca_id>` | CA-specific revocation lists |
| OCSP | `/api/ocsp` | Global responder for all CAs |
| AIA | `/api/certificates/ca/download` | Generic CA download |

## 📄 License

MIT License - see [LICENSE](LICENSE) file
