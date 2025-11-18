# Backend Architecture

The backend of VaulTLS is a monolithic application written in Rust using the Rocket web framework. The main components are:

*   **Rocket Server**: The core of the backend is a Rocket server that handles all incoming HTTP requests.
*   **SQLite Database**: VaulTLS uses a SQLite database to store all its data, including certificates, users, and settings. The database can be encrypted for extra security.
*   **OIDC Authentication**: The application supports OpenID Connect (OIDC) for authentication, allowing integration with external identity providers.
*   **Email Notifications**: VaulTLS can send email notifications for events like certificate expiration.

The backend code is organized into several modules:

*   `api`: Contains all the Rocket API endpoints.
*   `cert`: Handles certificate generation, signing, and other related operations.
*   `db`: Manages the SQLite database.
*   `auth`: Implements the authentication logic, including OIDC and password-based authentication.
*   `settings`: Manages the application settings.
*   `notification`: Handles email notifications.
*   `audit`: Implements the audit logging functionality.
*   `helper`: Contains helper functions used throughout the application.
*   `constants`: Defines constants used in the application.
*   `data`: Defines the data structures used in the application.

# Building and Running

## Docker (Recommended)

The easiest way to run VaulTLS is using Docker.

```bash
# Clone the repository
git clone https://github.com/7ritn/VaulTLS.git
cd VaulTLS

# Copy environment template
cp .env.example .env

# Start VaulTLS
docker-compose up -d
```

The frontend will be available at `http://localhost:4000` and the backend at `http://localhost:8000`.

## Local Development

For development, you can use the provided startup script.

```bash
# Make the startup script executable
chmod +x start-vaultls.sh

# Start both backend and frontend in development mode
./start-vaultls.sh start
```

The frontend will be available at `http://localhost:3000` and the backend at `http://localhost:8000`.

# Testing

To run the test suite:

```bash
cd backend
cargo test
```

# Development Conventions

*   **Rust**: Follow standard Rust formatting (`cargo fmt`).
*   **Vue.js**: Follow the Vue.js style guide.
*   **Commits**: Use the conventional commit format.
*   All new features must include comprehensive tests.

# Project Status and Roadmap

Based on the `tasklist.md` file, the project is actively being developed with a strong focus on security and the implementation of Certificate Revocation List (CRL) and Online Certificate Status Protocol (OCSP) features.

## CRL and OCSP Implementation

*   **CRL**: Fully implemented, including generation, signing, storage, caching, and distribution.
*   **OCSP**: Not yet implemented, but data structures are in place.

## Future Plans

The project has a detailed roadmap which includes:

*   **Automated Certificate Renewal**: A background job system for certificate renewal.
*   **Certificate Analytics Dashboard**: Advanced reporting and analytics.
*   **Hardware Security Module (HSM) Integration**: For enterprise key management.
*   **LDAP Integration**: For enterprise directory integration.
*   **Multi-CA Support**: To allow for multiple certificate authorities.
