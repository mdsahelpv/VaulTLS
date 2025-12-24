#!/bin/bash

# VaulTLS Application Startup Script
# This script sets up and starts both the backend and frontend components

set -e  # Exit on any error

# Determine script location for absolute path resolution
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="${SCRIPT_DIR}/backend"
FRONTEND_DIR="${SCRIPT_DIR}/frontend"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BACKEND_PORT=${BACKEND_PORT:-8000}
FRONTEND_PORT=${FRONTEND_PORT:-4000}
DB_PATH=${DB_PATH:-"${BACKEND_DIR}/database/database.db3"}
VAULTLS_DB_SECRET=${VAULTLS_DB_SECRET:-""}
VAULTLS_API_SECRET=${VAULTLS_API_SECRET:-"$(openssl rand -base64 32)"}

# PID and Log Files Location
LOGS_DIR="${SCRIPT_DIR}/logs"
mkdir -p "$LOGS_DIR"

# PID Files
BACKEND_PID_FILE="${LOGS_DIR}/backend.pid"
FRONTEND_PID_FILE="${LOGS_DIR}/frontend.pid"

# Log Files
BACKEND_LOG_FILE="${LOGS_DIR}/backend.log"
FRONTEND_LOG_FILE="${LOGS_DIR}/frontend.log"

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

# Function to check if a port is in use
check_port() {
    local port=$1
    if command_exists lsof; then
        lsof -i :$port >/dev/null 2>&1
    elif command_exists netstat; then
        netstat -tuln | grep -q ":$port "
    else
        # Fallback if neither lsof nor netstat is available (less reliable)
        return 1
    fi
}

# Function to check system requirements
check_requirements() {
    print_status "Checking system requirements..."

    local missing_reqs=0

    # Check for Rust
    if ! command_exists cargo; then
        print_error "Rust/Cargo is not installed. Please install Rust from https://rustup.rs/"
        missing_reqs=1
    else
        print_success "Rust/Cargo found: $(cargo --version)"
    fi

    # Check for Node.js
    if ! command_exists node; then
        print_error "Node.js is not installed. Please install Node.js from https://nodejs.org/"
        missing_reqs=1
    else
        print_success "Node.js found: $(node --version)"
    fi

    # Check for npm
    if ! command_exists npm; then
        print_error "npm is not installed. Please install npm with Node.js"
        missing_reqs=1
    else
        print_success "npm found: $(npm --version)"
    fi

    # Check for SQLite3 (optional)
    if command_exists sqlite3; then
        print_success "SQLite3 found: $(sqlite3 --version | head -n 1)"
    else
        print_warning "SQLite3 not found. Some database operations may not work."
    fi

    if [ $missing_reqs -eq 1 ]; then
        exit 1
    fi
}

# Function to setup backend
setup_backend() {
    print_status "Setting up backend..."

    cd "$BACKEND_DIR" || exit 1

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
    mkdir -p "$(dirname "$DB_PATH")"
    if [ ! -f "$DB_PATH" ]; then
        print_status "Setting up database..."
        # The database will be created automatically by the application
    fi

    print_success "Backend setup complete"
}

# Function to setup frontend
setup_frontend() {
    print_status "Setting up frontend..."

    cd "$FRONTEND_DIR" || exit 1

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

    print_success "Frontend setup complete"
}

# Function to check and clean stale PIDs
check_stale_pid() {
    local pid_file=$1
    local name=$2

    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ! kill -0 "$pid" 2>/dev/null; then
            print_warning "Found stale PID file for $name (PID: $pid). Removing..."
            rm -f "$pid_file"
        else
            print_error "$name is already running (PID: $pid)"
            return 1
        fi
    fi
    return 0
}

# Function to start backend
start_backend() {
    if ! check_stale_pid "$BACKEND_PID_FILE" "Backend"; then
        return
    fi

    if check_port "$BACKEND_PORT"; then
        print_error "Port $BACKEND_PORT is already in use. Cannot start backend."
        exit 1
    fi

    print_status "Starting backend server..."

    cd "$BACKEND_DIR" || exit 1

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
        nohup cargo run --release > "$BACKEND_LOG_FILE" 2>&1 &
    else
        print_status "Starting backend in development mode on port $BACKEND_PORT..."
        nohup cargo run > "$BACKEND_LOG_FILE" 2>&1 &
    fi

    echo $! > "$BACKEND_PID_FILE"
    local pid=$!

    # Wait a moment for the server to start
    sleep 3

    # Check if the server is running
    if kill -0 "$pid" 2>/dev/null; then
        print_success "Backend server started successfully (PID: $pid)"
        print_status "Backend logs: tail -f $(basename "$BACKEND_LOG_FILE")"
    else
        print_error "Failed to start backend server"
        cat "$BACKEND_LOG_FILE"
        exit 1
    fi
}

# Function to start frontend
start_frontend() {
    if ! check_stale_pid "$FRONTEND_PID_FILE" "Frontend"; then
        return
    fi

    if check_port "$FRONTEND_PORT"; then
        print_error "Port $FRONTEND_PORT is already in use. Cannot start frontend."
        exit 1
    fi

    print_status "Starting frontend server..."

    cd "$FRONTEND_DIR" || exit 1

    # Set environment variables
    export PORT=$FRONTEND_PORT
    export VITE_API_BASE_URL="http://localhost:$BACKEND_PORT"

    # Start the development server
    if [ "$1" = "production" ]; then
        print_status "Starting frontend in production mode on port $FRONTEND_PORT..."
        # For production, serve the built files
        if command_exists serve; then
            nohup npx serve -s dist -l $FRONTEND_PORT > "$FRONTEND_LOG_FILE" 2>&1 &
        elif command_exists http-server; then
            nohup npx http-server -p $FRONTEND_PORT -s dist > "$FRONTEND_LOG_FILE" 2>&1 &
        else
            print_error "Neither 'serve' nor 'http-server' found. Install with: npm install -g serve"
            exit 1
        fi
    else
        print_status "Starting frontend in development mode on port $FRONTEND_PORT..."
        nohup npm run dev -- --host 0.0.0.0 --port $FRONTEND_PORT > "$FRONTEND_LOG_FILE" 2>&1 &
    fi

    echo $! > "$FRONTEND_PID_FILE"
    local pid=$!

    # Wait a moment for the server to start
    sleep 5

    # Check if the server is running
    if kill -0 "$pid" 2>/dev/null; then
        print_success "Frontend server started successfully (PID: $pid)"
        print_status "Frontend logs: tail -f $(basename "$FRONTEND_LOG_FILE")"
    else
        print_error "Failed to start frontend server"
        cat "$FRONTEND_LOG_FILE"
        exit 1
    fi
}

# Function to stop services
stop_services() {
    print_status "Stopping services..."

    # Stop backend
    if [ -f "$BACKEND_PID_FILE" ]; then
        local pid=$(cat "$BACKEND_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            print_status "Stopping backend server (PID: $pid)..."
            kill "$pid"
            
            # Wait for process to exit
            local count=0
            while kill -0 "$pid" 2>/dev/null; do
                sleep 0.5
                count=$((count + 1))
                if [ $count -gt 20 ]; then
                    print_warning "Backend did not stop gracefully, forcing kill..."
                    kill -9 "$pid"
                    break
                fi
            done
            
            print_success "Backend server stopped"
        else
            print_warning "Backend PID file exists but process is not running"
        fi
        rm -f "$BACKEND_PID_FILE"
    else
        print_status "Backend is not running (no PID file)"
    fi

    # Ensure backend port is free
    if check_port "$BACKEND_PORT"; then
        print_warning "Port $BACKEND_PORT is still in use. Killing process holding it..."
        if command_exists lsof; then
            local pid=$(lsof -t -i :$BACKEND_PORT)
            if [ -n "$pid" ]; then
                kill -9 $pid
                print_success "Killed process $pid holding port $BACKEND_PORT"
            fi
        elif command_exists fuser; then
            fuser -k -n tcp $BACKEND_PORT
            print_success "Killed process holding port $BACKEND_PORT"
        fi
    fi

    # Stop frontend
    if [ -f "$FRONTEND_PID_FILE" ]; then
        local pid=$(cat "$FRONTEND_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            print_status "Stopping frontend server (PID: $pid)..."
            kill "$pid"
            
            # Wait for process to exit
            local count=0
            while kill -0 "$pid" 2>/dev/null; do
                sleep 0.5
                count=$((count + 1))
                if [ $count -gt 20 ]; then
                    print_warning "Frontend did not stop gracefully, forcing kill..."
                    kill -9 "$pid"
                    break
                fi
            done

            print_success "Frontend server stopped"
        else
            print_warning "Frontend PID file exists but process is not running"
        fi
        rm -f "$FRONTEND_PID_FILE"
    else
        print_status "Frontend is not running (no PID file)"
    fi

    # Ensure frontend port is free
    if check_port "$FRONTEND_PORT"; then
        print_warning "Port $FRONTEND_PORT is still in use. Killing process holding it..."
        if command_exists lsof; then
            local pid=$(lsof -t -i :$FRONTEND_PORT)
            if [ -n "$pid" ]; then
                kill -9 $pid
                print_success "Killed process $pid holding port $FRONTEND_PORT"
            fi
        elif command_exists fuser; then
            fuser -k -n tcp $FRONTEND_PORT
            print_success "Killed process holding port $FRONTEND_PORT"
        fi
    fi
}

# Function to show status
show_status() {
    echo "=== VaulTLS Application Status ==="

    if [ -f "$BACKEND_PID_FILE" ]; then
        local pid=$(cat "$BACKEND_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "Backend:   ${GREEN}Running${NC} (PID: $pid, Port: $BACKEND_PORT)"
        else
            echo -e "Backend:   ${RED}Stopped${NC} (PID file exists but process not running)"
        fi
    else
        echo -e "Backend:   ${RED}Not running${NC}"
    fi

    if [ -f "$FRONTEND_PID_FILE" ]; then
        local pid=$(cat "$FRONTEND_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "Frontend:  ${GREEN}Running${NC} (PID: $pid, Port: $FRONTEND_PORT)"
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
    echo "Backend:   $(basename "$BACKEND_LOG_FILE")"
    echo "Frontend:  $(basename "$FRONTEND_LOG_FILE")"
}

# Function to show logs
show_logs() {
    if [ -f "$BACKEND_LOG_FILE" ]; then
        echo "=== Backend Logs ==="
        tail -n 20 "$BACKEND_LOG_FILE"
        echo ""
    fi

    if [ -f "$FRONTEND_LOG_FILE" ]; then
        echo "=== Frontend Logs ==="
        tail -n 20 "$FRONTEND_LOG_FILE"
        echo ""
    fi
}

# Function to clean artifacts
clean_artifacts() {
    print_status "Cleaning build artifacts and logs..."

    # Clean Rust artifacts
    if [ -d "$BACKEND_DIR" ]; then
        cd "$BACKEND_DIR"
        cargo clean
    fi

    # Clean Node.js artifacts
    if [ -d "$FRONTEND_DIR" ]; then
        cd "$FRONTEND_DIR"
        rm -rf node_modules dist
    fi

    # Remove log files and PID files
    rm -f "$BACKEND_LOG_FILE" "$FRONTEND_LOG_FILE" "$BACKEND_PID_FILE" "$FRONTEND_PID_FILE"

    print_success "Cleanup complete"
}

# Function to show interactive menu
show_menu() {
    while true; do
        clear
        echo -e "${BLUE}=== VaulTLS Application Manager ===${NC}"
        echo ""
        show_status
        echo ""
        echo "Please select an option:"
        echo "1) Start Services"
        echo "2) Stop Services"
        echo "3) Restart Services"
        echo "4) Check Status"
        echo "5) View Logs"
        echo "6) Check Requirements & Ports"
        echo "7) Clean Artifacts"
        echo "8) Clean Start (Fresh)"
        echo "9) Exit"
        echo ""
        read -p "Enter choice [1-9]: " choice

        case $choice in
            1)
                print_status "Starting services..."
                check_requirements
                setup_backend "debug"
                setup_frontend "development"
                start_backend "debug"
                start_frontend "development"
                show_status
                read -p "Press Enter to continue..."
                ;;
            2)
                stop_services
                read -p "Press Enter to continue..."
                ;;
            3)
                print_status "Restarting services..."
                stop_services
                sleep 2
                start_backend "debug"
                start_frontend "development"
                show_status
                read -p "Press Enter to continue..."
                ;;
            4)
                show_status
                read -p "Press Enter to continue..."
                ;;
            5)
                show_logs
                read -p "Press Enter to continue..."
                ;;
            6)
                check_requirements
                print_status "Checking ports..."
                if check_port "$BACKEND_PORT"; then
                    print_warning "Backend port $BACKEND_PORT is in use"
                else
                    print_success "Backend port $BACKEND_PORT is free"
                fi
                if check_port "$FRONTEND_PORT"; then
                    print_warning "Frontend port $FRONTEND_PORT is in use"
                else
                    print_success "Frontend port $FRONTEND_PORT is free"
                fi
                read -p "Press Enter to continue..."
                ;;
            7)
                clean_artifacts
                read -p "Press Enter to continue..."
                ;;
            8)
                print_status "Performing clean start..."
                # Clean start logic duplicated here or call main with clean-start
                # Calling main recursively might be tricky with args, but clean-start takes no extra args usually
                # Better to just call the logic directly or via a function. 
                # Since main handles clean-start, let's just run the commands.
                
                print_status "Performing clean start - removing all remnants..."
                stop_services
                sleep 1

                # Clean all remnants
                print_status "Cleaning old database files..."
                rm -f "$DB_PATH" "${DB_PATH}-shm" "${DB_PATH}-wal"
                rm -f "$BACKEND_DIR/ca.cert" "$BACKEND_DIR/settings.json"
                rm -f "$BACKEND_LOG_FILE" "$FRONTEND_LOG_FILE" "$BACKEND_PID_FILE" "$FRONTEND_PID_FILE"

                print_status "Cleaning build artifacts..."
                clean_artifacts

                print_success "Clean start complete. Starting fresh..."
                check_requirements
                setup_backend "debug"
                setup_frontend "development"
                start_backend "debug"
                start_frontend "development"
                show_status
                
                read -p "Press Enter to continue..."
                ;;
            9)
                print_status "Exiting..."
                exit 0
                ;;
            *)
                print_error "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# Main script logic
main() {
    local command=""
    local backend_mode="debug"
    local frontend_mode="development"

    # If no arguments provided, show menu
    if [ $# -eq 0 ]; then
        show_menu
        exit 0
    fi

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            start|clean-start|stop|restart|status|setup|backend|frontend|logs|clean|check)
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
            print_status "Starting VaulTLS application..."
            check_requirements
            setup_backend "$backend_mode"
            setup_frontend "$frontend_mode"
            start_backend "$backend_mode"
            start_frontend "$frontend_mode"
            show_status
            print_success "VaulTLS application started successfully in background!"
            print_status "Use '$0 stop' to stop all services"
            ;;
        clean-start)
            print_status "Performing clean start - removing all remnants..."
            stop_services
            sleep 1

            # Clean all remnants
            print_status "Cleaning old database files..."
            rm -f "$BACKEND_DIR/database.db3" "$BACKEND_DIR/database.db3-shm" "$BACKEND_DIR/database.db3-wal"
            rm -f "$BACKEND_DIR/ca.cert" "$BACKEND_DIR/settings.json"
            rm -f "$BACKEND_LOG_FILE" "$FRONTEND_LOG_FILE" "$BACKEND_PID_FILE" "$FRONTEND_PID_FILE"

            print_status "Cleaning build artifacts..."
            clean_artifacts

            print_success "Clean start complete. Starting fresh..."
            check_requirements
            setup_backend "$backend_mode"
            setup_frontend "$frontend_mode"
            start_backend "$backend_mode"
            start_frontend "$frontend_mode"
            show_status
            print_success "VaulTLS application started fresh in background!"
            ;;
        stop)
            stop_services
            ;;
        restart)
            print_status "Restarting services..."
            stop_services
            sleep 2
            start_backend "$backend_mode"
            start_frontend "$frontend_mode"
            show_status
            print_success "Services restarted"
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
        backend)
            check_requirements
            setup_backend "$backend_mode"
            start_backend "$backend_mode"
            print_success "Backend started successfully in background!"
            ;;
        frontend)
            check_requirements
            setup_frontend "$frontend_mode"
            start_frontend "$frontend_mode"
            print_success "Frontend started successfully in background!"
            ;;
        logs)
            show_logs
            ;;
        clean)
            clean_artifacts
            ;;
        check)
            check_requirements
            print_status "Checking ports..."
            if check_port "$BACKEND_PORT"; then
                print_warning "Backend port $BACKEND_PORT is in use"
            else
                print_success "Backend port $BACKEND_PORT is free"
            fi
            if check_port "$FRONTEND_PORT"; then
                print_warning "Frontend port $FRONTEND_PORT is in use"
            else
                print_success "Frontend port $FRONTEND_PORT is free"
            fi
            ;;
        *)
            print_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Function to show help
show_help() {
    echo "VaulTLS Application Startup Script"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  start          Start both backend and frontend (default)"
    echo "  clean-start    Clean all remnants and start fresh"
    echo "  stop           Stop both services"
    echo "  restart        Restart both services"
    echo "  status         Show status of services"
    echo "  check          Check system requirements and ports"
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
}

# Run main function with all arguments
main "$@"
