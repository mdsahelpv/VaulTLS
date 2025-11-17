#!/bin/bash

# VaulTLS Application Startup Script
# This script sets up and starts both the backend and frontend components

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BACKEND_PORT=${BACKEND_PORT:-8000}
FRONTEND_PORT=${FRONTEND_PORT:-4000}
DB_PATH=${DB_PATH:-"./backend/database.db3"}
VAULTLS_DB_SECRET=${VAULTLS_DB_SECRET:-""}
VAULTLS_API_SECRET=${VAULTLS_API_SECRET:-"$(openssl rand -base64 32)"}

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check system requirements
check_requirements() {
    print_status "Checking system requirements..."

    # Check for Rust
    if ! command_exists cargo; then
        print_error "Rust/Cargo is not installed. Please install Rust from https://rustup.rs/"
        exit 1
    fi
    print_success "Rust/Cargo found: $(cargo --version)"

    # Check for Node.js
    if ! command_exists node; then
        print_error "Node.js is not installed. Please install Node.js from https://nodejs.org/"
        exit 1
    fi
    print_success "Node.js found: $(node --version)"

    # Check for npm
    if ! command_exists npm; then
        print_error "npm is not installed. Please install npm with Node.js"
        exit 1
    fi
    print_success "npm found: $(npm --version)"

    # Check for SQLite3 (optional, for database operations)
    if command_exists sqlite3; then
        print_success "SQLite3 found: $(sqlite3 --version | head -n 1)"
    else
        print_warning "SQLite3 not found. Some database operations may not work."
    fi
}

# Function to setup backend
setup_backend() {
    print_status "Setting up backend..."

    cd backend

    # Check if Cargo.toml exists
    if [ ! -f "Cargo.toml" ]; then
        print_error "Cargo.toml not found in backend directory"
        exit 1
    fi

    # Install/update dependencies
    print_status "Installing/updating Rust dependencies..."
    cargo update

    # Build the project
    print_status "Building backend..."
    if [ "$1" = "release" ]; then
        cargo build --release
    else
        cargo build
    fi

    # Setup database if it doesn't exist
    if [ ! -f "$DB_PATH" ]; then
        print_status "Setting up database..."
        # The database will be created automatically by the application
        # when it first runs and connects to it
    fi

    cd ..
    print_success "Backend setup complete"
}

# Function to setup frontend
setup_frontend() {
    print_status "Setting up frontend..."

    cd frontend

    # Check if package.json exists
    if [ ! -f "package.json" ]; then
        print_error "package.json not found in frontend directory"
        exit 1
    fi

    # Install dependencies
    print_status "Installing Node.js dependencies..."
    npm install

    # Build the project
    print_status "Building frontend..."
    if [ "$1" = "production" ]; then
        npm run build
    fi

    cd ..
    print_success "Frontend setup complete"
}

# Function to start backend
start_backend() {
    print_status "Starting backend server..."

    cd backend

    # Set environment variables
    export ROCKET_ADDRESS=0.0.0.0
    export ROCKET_PORT=$BACKEND_PORT
    export VAULTLS_API_SECRET="$VAULTLS_API_SECRET"

    if [ -n "$VAULTLS_DB_SECRET" ]; then
        export VAULTLS_DB_SECRET="$VAULTLS_DB_SECRET"
        print_status "Database encryption enabled"
    fi

    # Start the server
    if [ "$1" = "release" ]; then
        print_status "Starting backend in release mode on port $BACKEND_PORT..."
        nohup cargo run --release > ../backend.log 2>&1 &
    else
        print_status "Starting backend in development mode on port $BACKEND_PORT..."
        nohup cargo run > ../backend.log 2>&1 &
    fi

    BACKEND_PID=$!
    echo $BACKEND_PID > ../backend.pid

    # Wait a moment for the server to start
    sleep 3

    # Check if the server is running
    if kill -0 $BACKEND_PID 2>/dev/null; then
        print_success "Backend server started successfully (PID: $BACKEND_PID)"
        print_status "Backend logs: tail -f backend.log"
    else
        print_error "Failed to start backend server"
        cat ../backend.log
        exit 1
    fi

    cd ..
}

# Function to start frontend
start_frontend() {
    print_status "Starting frontend server..."

    cd frontend

    # Set environment variables
    export PORT=$FRONTEND_PORT
    export VITE_API_BASE_URL="http://localhost:$BACKEND_PORT"

    # Start the development server
    if [ "$1" = "production" ]; then
        print_status "Starting frontend in production mode on port $FRONTEND_PORT..."
        # For production, serve the built files
        if command_exists serve; then
            nohup npx serve -s dist -l $FRONTEND_PORT > ../frontend.log 2>&1 &
        elif command_exists http-server; then
            nohup npx http-server -p $FRONTEND_PORT -s dist > ../frontend.log 2>&1 &
        else
            print_error "Neither 'serve' nor 'http-server' found. Install with: npm install -g serve"
            exit 1
        fi
    else
        print_status "Starting frontend in development mode on port $FRONTEND_PORT..."
        nohup npm run dev -- --host 0.0.0.0 --port $FRONTEND_PORT > ../frontend.log 2>&1 &
    fi

    FRONTEND_PID=$!
    echo $FRONTEND_PID > ../frontend.pid

    # Wait a moment for the server to start
    sleep 5

    # Check if the server is running
    if kill -0 $FRONTEND_PID 2>/dev/null; then
        print_success "Frontend server started successfully (PID: $FRONTEND_PID)"
        print_status "Frontend logs: tail -f frontend.log"
    else
        print_error "Failed to start frontend server"
        cat ../frontend.log
        exit 1
    fi

    cd ..
}

# Function to stop services
stop_services() {
    print_status "Stopping services..."

    # Stop backend
    if [ -f "backend.pid" ]; then
        BACKEND_PID=$(cat backend.pid)
        if kill -0 $BACKEND_PID 2>/dev/null; then
            print_status "Stopping backend server (PID: $BACKEND_PID)..."
            kill $BACKEND_PID
            wait $BACKEND_PID 2>/dev/null
            print_success "Backend server stopped"
        fi
        rm -f backend.pid
    fi

    # Stop frontend
    if [ -f "frontend.pid" ]; then
        FRONTEND_PID=$(cat frontend.pid)
        if kill -0 $FRONTEND_PID 2>/dev/null; then
            print_status "Stopping frontend server (PID: $FRONTEND_PID)..."
            kill $FRONTEND_PID
            wait $FRONTEND_PID 2>/dev/null
            print_success "Frontend server stopped"
        fi
        rm -f frontend.pid
    fi
}

# Function to stop backend only
stop_backend_only() {
    print_status "Stopping backend service only..."

    if [ -f "backend.pid" ]; then
        BACKEND_PID=$(cat backend.pid)
        if kill -0 $BACKEND_PID 2>/dev/null; then
            print_status "Stopping backend server (PID: $BACKEND_PID)..."
            kill $BACKEND_PID
            wait $BACKEND_PID 2>/dev/null
            print_success "Backend server stopped"
        fi
        rm -f backend.pid
    else
        print_warning "Backend does not appear to be running (no PID file found)"
    fi
}

# Function to stop frontend only
stop_frontend_only() {
    print_status "Stopping frontend service only..."

    if [ -f "frontend.pid" ]; then
        FRONTEND_PID=$(cat frontend.pid)
        if kill -0 $FRONTEND_PID 2>/dev/null; then
            print_status "Stopping frontend server (PID: $FRONTEND_PID)..."
            kill $FRONTEND_PID
            wait $FRONTEND_PID 2>/dev/null
            print_success "Frontend server stopped"
        fi
        rm -f frontend.pid
    else
        print_warning "Frontend does not appear to be running (no PID file found)"
    fi
}

# Function to show status
show_status() {
    echo "=== VaulTLS Application Status ==="

    if [ -f "backend.pid" ]; then
        BACKEND_PID=$(cat backend.pid)
        if kill -0 $BACKEND_PID 2>/dev/null; then
            echo -e "Backend:   ${GREEN}Running${NC} (PID: $BACKEND_PID, Port: $BACKEND_PORT)"
        else
            echo -e "Backend:   ${RED}Stopped${NC} (PID file exists but process not running)"
        fi
    else
        echo -e "Backend:   ${RED}Not running${NC}"
    fi

    if [ -f "frontend.pid" ]; then
        FRONTEND_PID=$(cat frontend.pid)
        if kill -0 $FRONTEND_PID 2>/dev/null; then
            echo -e "Frontend:  ${GREEN}Running${NC} (PID: $FRONTEND_PID, Port: $FRONTEND_PORT)"
        else
            echo -e "Frontend:  ${RED}Stopped${NC} (PID file exists but process not running)"
        fi
    else
        echo -e "Frontend:  ${RED}Not running${NC}"
    fi

    echo ""
    echo "=== Access URLs ==="
    echo "Frontend:  http://localhost:$FRONTEND_PORT"
    echo "Backend:   http://localhost:$BACKEND_PORT"
    echo ""
    echo "=== Log Files ==="
    echo "Backend:   backend.log"
    echo "Frontend:  frontend.log"
}

# Function to show help
show_help() {
    echo "VaulTLS Application Startup Script"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  start          Start both backend and frontend (interactive choice)"
    echo "  start [1-3]    Start backend(1), frontend(2), both(3) with no prompt"
    echo "  clean-start    Clean all remnants and start fresh"
    echo "  stop           Stop services (interactive choice: backend/frontend/both)"
    echo "  stop [1-3]     Stop backend(1), frontend(2), both(3) with no prompt"
    echo "  status         Show status of services"
    echo "  setup          Setup both backend and frontend without starting"
    echo "  backend        Start only backend"
    echo "  frontend       Start only frontend"
    echo "  logs           Show logs from both services"
    echo "  clean          Clean build artifacts and logs"
    echo ""
    echo "Options:"
    echo "  --release      Start backend in release mode"
    echo "  --production   Start frontend in production mode"
    echo "  --port PORT    Set backend port (default: 8000)"
    echo "  --frontend-port PORT    Set frontend port (default: 4000)"
    echo "  --help         Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  BACKEND_PORT           Backend server port (default: 8000)"
    echo "  FRONTEND_PORT          Frontend server port (default: 4000)"
    echo "  VAULTLS_API_SECRET     API secret key (default: development key)"
    echo "  VAULTLS_DB_SECRET      Database encryption secret"
    echo "  DB_PATH                Database file path (default: ./backend/database.db3)"
    echo ""
    echo "Examples:"
    echo "  $0 start                    # Start services (interactive menu)"
    echo "  $0 start 1                  # Start backend only (no prompt)"
    echo "  $0 start 2                  # Start frontend only (no prompt)"
    echo "  $0 start 3                  # Start both services (no prompt)"
    echo "  $0 stop                     # Stop services (interactive menu)"
    echo "  $0 stop 1                   # Stop backend only (no prompt)"
    echo "  $0 stop 2                   # Stop frontend only (no prompt)"
    echo "  $0 stop 3                   # Stop both services (no prompt)"
    echo "  $0 start --release          # Start both with backend in release mode"
    echo "  $0 backend --port 9000      # Start backend on custom port"
    echo "  $0 status                   # Show status of running services"
    echo "  $0 logs                     # Show logs from both services"
}

# Function to show logs
show_logs() {
    if [ -f "backend.log" ]; then
        echo "=== Backend Logs ==="
        tail -n 20 backend.log
        echo ""
    fi

    if [ -f "frontend.log" ]; then
        echo "=== Frontend Logs ==="
        echo "=== Frontend Logs ==="
        tail -n 20 frontend.log
        echo ""
    fi
}

# Function to clean artifacts
clean_artifacts() {
    print_status "Cleaning build artifacts and logs..."

    # Clean Rust artifacts
    cd backend
    cargo clean
    cd ..

    # Clean Node.js artifacts
    cd frontend
    rm -rf node_modules dist
    cd ..

    # Remove log files and PID files
    rm -f backend.log frontend.log backend.pid frontend.pid

    print_success "Cleanup complete"
}

# Main script logic
main() {
    local command="start"
    local choice=""
    local backend_mode="debug"
    local frontend_mode="development"

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            start|stop)
                command="$1"
                shift
                # Check if next argument is a number (1-3)
                if [[ $# -gt 0 && $1 =~ ^[1-3]$ ]]; then
                    choice="$1"
                    shift
                fi
                ;;
            status|setup|logs|clean)
                command="$1"
                shift
                ;;
            --release)
                backend_mode="release"
                shift
                ;;
            --production)
                frontend_mode="production"
                shift
                ;;
            --port)
                BACKEND_PORT="$2"
                shift 2
                ;;
            --frontend-port)
                FRONTEND_PORT="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    case $command in
        start)
            check_requirements

            if [ -z "$choice" ]; then
                print_status "Start Services Options:"
                print_status "  1) Start backend only"
                print_status "  2) Start frontend only"
                print_status "  3) Start both services"

                echo ""
                read -p "Enter your choice (1-3) [3]: " choice
                choice=${choice:-3}  # Default to option 3
            fi

            case $choice in
                1)
                    setup_backend "$backend_mode"
                    start_backend "$backend_mode"
                    print_success "Backend started successfully in background!"
                    print_status "Use '$0 stop 1' to stop backend only"
                    ;;
                2)
                    setup_frontend "$frontend_mode"
                    start_frontend "$frontend_mode"
                    print_success "Frontend started successfully in background!"
                    print_status "Use '$0 stop 2' to stop frontend only"
                    ;;
                3)
                    setup_backend "$backend_mode"
                    setup_frontend "$frontend_mode"
                    start_backend "$backend_mode"
                    start_frontend "$frontend_mode"
                    show_status
                    print_success "VaulTLS application started successfully in background!"
                    print_status "Use '$0 stop' to stop all services"
                    ;;
                *)
                    print_error "Invalid choice. Use 1-3."
                    exit 1
                    ;;
            esac
            ;;
        stop)
            if [ -z "$choice" ]; then
                print_status "Stop Services Options:"
                print_status "  1) Stop backend only"
                print_status "  2) Stop frontend only"
                print_status "  3) Stop both services"

                echo ""
                read -p "Enter your choice (1-3) [3]: " choice
                choice=${choice:-3}  # Default to option 3
            fi

            case $choice in
                1)
                    stop_backend_only
                    ;;
                2)
                    stop_frontend_only
                    ;;
                3)
                    stop_services
                    ;;
                *)
                    print_error "Invalid choice. Use 1-3."
                    exit 1
                    ;;
            esac
            ;;
        status)
            show_status
            ;;
        setup)
            check_requirements
            setup_backend "$backend_mode"
            setup_frontend "$frontend_mode"
            print_success "Setup complete. Run '$0 start' to start the services."
            ;;

        logs)
            show_logs
            ;;
        clean)
            clean_artifacts
            ;;
        *)
            print_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
        clean)
            clean_artifacts
            ;;
        *)
            print_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
