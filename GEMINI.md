# GEMINI.md

## Project Overview

This project is **VaulTLS**, a comprehensive, enterprise-grade solution for managing mTLS (mutual TLS) certificates. It provides a centralized platform for generating, managing, and distributing client and server TLS certificates.

The project is a web application with a **Rust backend** and a **Vue.js frontend**.

*   **Backend:** The backend is a Rocket-based web server written in Rust. It uses `rusqlite` with SQLCipher for an encrypted database, `openssl` for cryptographic operations, and `jsonwebtoken` for authentication. It provides a RESTful API for managing certificates, users, and settings.

*   **Frontend:** The frontend is a Vue.js single-page application built with Vite. It uses Pinia for state management, Vue Router for routing, and Bootstrap for styling. It communicates with the backend via a RESTful API.

## Building and Running

### Production (Docker)

The recommended way to run VaulTLS is using Docker.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/7ritn/VaulTLS.git
    cd VaulTLS
    ```

2.  **Copy environment template:**
    ```bash
    cp .env.example .env
    ```

3.  **Start VaulTLS:**
    ```bash
    docker-compose up -d
    ```

The frontend will be available at `http://localhost:4000` and the backend at `http://localhost:8000`.

### Development (Local)

For development, a startup script is provided to manage the backend and frontend services.

1.  **Prerequisites:**
    *   Rust (latest stable)
    *   Node.js (v16+)

2.  **Clone the repository:**
    ```bash
    git clone https://github.com/7ritn/VaulTLS.git
    cd VaulTLS
    ```

3.  **Make the startup script executable:**
    ```bash
    chmod +x start-vaultls.sh
    ```

4.  **Start both backend and frontend in development mode:**
    ```bash
    ./start-vaultls.sh start
    ```

The frontend will be available at `http://localhost:3000` and the backend at `http://localhost:8000`.

The `start-vaultls.sh` script provides other commands for managing the services:

*   `./start-vaultls.sh status`: Check service status
*   `./start-vaultls.sh logs`: View service logs
*   `./start-vaultls.sh stop`: Stop all services
*   `./start-vaultls.sh restart`: Restart services

### Testing

The backend has a comprehensive test suite.

*   **Run all tests:**
    ```bash
    cd backend
    cargo test
    ```

The frontend uses Playwright for end-to-end testing.

*   **Run all tests:**
    ```bash
    cd frontend
    npm run test
    ```

## Development Conventions

*   **Rust:** Follow standard Rust formatting (`cargo fmt`).
*   **Vue.js:** Follow Vue.js style guide.
*   **Commits:** Use conventional commit format.
*   **Testing:** All new features must include comprehensive tests.
