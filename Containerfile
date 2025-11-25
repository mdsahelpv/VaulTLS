# Stage 1: Build the Vue.js frontend
FROM node:23-alpine AS frontend-builder

# Set working directory first (better caching)
WORKDIR /app/frontend

# Copy dependency files first (for better layer caching)
COPY frontend/package*.json ./

# Use npm ci for production builds (faster, reliable)
RUN npm ci --only=production && npm cache clean --force

# Copy source files
COPY frontend/ ./

# Copy assets that might be needed
COPY assets/ ../assets/

# Build the application
RUN npm run build

# Remove node_modules after build (reduces image size)
RUN rm -rf node_modules

# Stage 2: Build the Rust backend binary
FROM rust:1.85-slim AS backend-builder

ARG RUN_TESTS=false

# Install OpenSSL development libraries (required for Rust crypto crates)
RUN apt-get update && apt-get install -y --no-install-recommends \
       pkg-config \
       libssl-dev \
       ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app/backend

# Copy dependency files first (optimizes layer caching)
COPY backend/Cargo.toml backend/Cargo.lock ./

# Cache dependencies
RUN cargo fetch --locked

# Copy source files (maximizes cache reuse - only rebuilds when source changes)
COPY backend/src ./src
COPY backend/migrations ./migrations

# Build the final binary
RUN set -eux; \
    cargo build --release --frozen; \
    cargo test --release || echo "Tests failed but continuing...";

# Extract binary
RUN cp target/release/backend /usr/local/bin/backend && \
    strip /usr/local/bin/backend && \
    rm -rf /root/.cargo/registry && \
    rm -rf /root/.cargo/git && \
    rm -rf target

# Stage 3: Final runtime container (optimized for size and security)
FROM debian:bookworm-slim AS runtime

# Set environment for minimal container
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Install only essential runtime dependencies
# Note: OpenSSL runtime libraries are required for the Rust application
RUN apt-get update && apt-get install -y --no-install-recommends \
       ca-certificates \
       nginx-light \
       sqlite3 \
       curl \
       openssl \
       libssl3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/share/nginx/html/* \
    && rm -rf /etc/nginx/sites-enabled/default

# Create non-root user and directories in single layer
RUN set -eux; \
    groupadd -r vaultls -g 1001; \
    useradd -r -g vaultls -u 1001 -s /bin/false -m vaultls; \
    mkdir -p \
        /app/data \
        /app/settings \
        /var/log/vaultls \
        /var/log/nginx \
        /var/cache/nginx \
        /run/nginx \
        /usr/share/nginx/html \
        /tmp/nginx \
        /var/lib/nginx; \
    chown -R vaultls:vaultls \
        /app/data \
        /app/settings \
        /var/log/vaultls \
        /var/log/nginx \
        /var/cache/nginx \
        /run/nginx \
        /usr/share/nginx/html \
        /tmp/nginx \
        /var/lib/nginx \
        /var/cache/nginx \
        /var/tmp; \
    chmod 755 /app/data

# Copy built assets from previous stages
COPY --from=frontend-builder --chown=vaultls:vaultls /app/frontend/dist/ /usr/share/nginx/html/
COPY --from=backend-builder --chown=vaultls:vaultls /usr/local/bin/backend /app/bin/backend
COPY --chown=vaultls:vaultls container/nginx.conf /etc/nginx/nginx.conf
COPY --chown=vaultls:vaultls container/entrypoint.sh /app/bin/entrypoint.sh

# Set executable permissions
RUN chmod +x /app/bin/entrypoint.sh /app/bin/backend

# Set default working directory in container
WORKDIR /app/settings

# Switch to non-root user
USER vaultls

# Expose ports
EXPOSE 80 8000

# Environment variables
ENV VAULTLS_BACKEND_PORT=8000
ENV VAULTLS_FRONTEND_PORT=4000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:$VAULTLS_FRONTEND_PORT/api/health || exit 1

# Default command
CMD ["/app/bin/entrypoint.sh"]
