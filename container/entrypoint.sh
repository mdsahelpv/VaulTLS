#!/bin/bash
set -e

# VaulTLS Container Entrypoint Script
# Manages starting both the backend and frontend services

echo "🏁 Starting VaulTLS container..."

# Set default environment variables if not provided
export VAULTLS_BACKEND_PORT=${VAULTLS_BACKEND_PORT:-8000}
export VAULTLS_FRONTEND_PORT=${VAULTLS_FRONTEND_PORT:-4000}
export ROCKET_ADDRESS=${ROCKET_ADDRESS:-0.0.0.0}
export ROCKET_PORT=${ROCKET_PORT:-8000}
export VAULTLS_API_SECRET=${VAULTLS_API_SECRET:-$(openssl rand -base64 32)}

# Create necessary directories
mkdir -p /app/data /tmp/vaultls

# Generate API secret if not set
if [ -z "$VAULTLS_API_SECRET" ]; then
    echo "🔑 Generating API secret..."
    VAULTLS_API_SECRET=$(openssl rand -base64 32)
    export VAULTLS_API_SECRET
fi

# Function to start nginx
start_nginx() {
    echo "🌐 Starting nginx web server..."
    nginx -g "daemon off;" &
    NGINX_PID=$!
    echo "✅ nginx started (PID: $NGINX_PID)"

    # Wait a moment for nginx to start
    sleep 2

    # Check if nginx is still running
    if ! kill -0 $NGINX_PID 2>/dev/null; then
        echo "❌ nginx failed to start"
        cat /var/log/nginx/error.log
        exit 1
    fi
}

# Function to start backend
start_backend() {
    echo "🚀 Starting backend service..."
    /app/bin/backend &
    BACKEND_PID=$!
    echo "✅ backend started (PID: $BACKEND_PID)"

    # Wait a moment for backend to start
    sleep 3

    # Check if backend is still running
    if ! kill -0 $BACKEND_PID 2>/dev/null; then
        echo "❌ backend failed to start"
        exit 1
    fi
}

# Function to wait for services
wait_for_services() {
    echo "⏳ Monitoring services..."
    wait
}

# Function to handle shutdown
cleanup() {
    echo ""
    echo "🛑 Shutting down services..."

    # Stop backend
    if [ -n "$BACKEND_PID" ]; then
        echo "Stopping backend (PID: $BACKEND_PID)"
        kill $BACKEND_PID 2>/dev/null || true
        wait $BACKEND_PID 2>/dev/null || true
    fi

    # Stop nginx
    if [ -n "$NGINX_PID" ]; then
        echo "Stopping nginx (PID: $NGINX_PID)"
        nginx -s quit 2>/dev/null || true
        # Give nginx time to gracefully shut down
        for i in {1..10}; do
            if ! kill -0 $NGINX_PID 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
        # Force kill if still running
        kill $NGINX_PID 2>/dev/null || true
        wait $NGINX_PID 2>/dev/null || true
    fi

    echo "✅ All services stopped"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Start services
start_nginx
start_backend

echo "🎉 VaulTLS is running!"
echo "   📍 Frontend: http://localhost:$VAULTLS_FRONTEND_PORT"
echo "   🔗 Backend:  http://localhost:$VAULTLS_BACKEND_PORT"
echo "   📊 Status: http://localhost:$VAULTLS_FRONTEND_PORT (health checks)"

# Wait for services
wait_for_services
