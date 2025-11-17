#!/bin/bash

# VaulTLS Application Manager
# A simple, intuitive tool to manage your VaulTLS application

set -e

# ============================================================================
# STYLING & COLORS
# ============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Unicode symbols (with ASCII fallbacks)
if [[ "$TERM" != "dumb" ]] && [[ -t 1 ]]; then
    CHECK="✓"
    CROSS="✗"
    ARROW="→"
    DOT="•"
    ROCKET="🚀"
    GEAR="⚙"
    STOP="■"
else
    CHECK="+"
    CROSS="x"
    ARROW=">"
    DOT="*"
    ROCKET=">"
    GEAR="*"
    STOP="[]"
fi

# ============================================================================
# CONFIGURATION
# ============================================================================
BACKEND_PORT=${BACKEND_PORT:-8000}
FRONTEND_PORT=${FRONTEND_PORT:-4000}
DB_PATH=${DB_PATH:-"./backend/database.db3"}
VAULTLS_DB_SECRET=${VAULTLS_DB_SECRET:-""}
VAULTLS_API_SECRET=${VAULTLS_API_SECRET:-"$(openssl rand -base64 32 2>/dev/null || echo 'dev-secret-key')"}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

print_header() {
    echo ""
    echo -e "${BOLD}${CYAN}╔════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║${NC}      ${BOLD}VaulTLS Application Manager${NC}     ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}╚════════════════════════════════════════╝${NC}"
    echo ""
}

print_status() {
    echo -e "${BLUE}${ARROW}${NC} ${DIM}$1${NC}"
}

print_success() {
    echo -e "${GREEN}${CHECK}${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}${DOT}${NC} $1"
}

print_error() {
    echo -e "${RED}${CROSS}${NC} $1"
}

print_divider() {
    echo -e "${DIM}────────────────────────────────────────${NC}"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ============================================================================
# SYSTEM CHECKS
# ============================================================================

check_requirements() {
    local all_good=true
    
    echo -e "${BOLD}Checking system requirements...${NC}"
    echo ""
    
    # Check Rust
    if command_exists cargo; then
        print_success "Rust/Cargo $(cargo --version | cut -d' ' -f2)"
    else
        print_error "Rust/Cargo not found - Install from ${CYAN}https://rustup.rs/${NC}"
        all_good=false
    fi
    
    # Check Node.js
    if command_exists node; then
        print_success "Node.js $(node --version)"
    else
        print_error "Node.js not found - Install from ${CYAN}https://nodejs.org/${NC}"
        all_good=false
    fi
    
    # Check npm
    if command_exists npm; then
        print_success "npm $(npm --version)"
    else
        print_error "npm not found - Install with Node.js"
        all_good=false
    fi
    
    # Check SQLite (optional)
    if command_exists sqlite3; then
        print_success "SQLite3 $(sqlite3 --version | cut -d' ' -f1)"
    else
        print_warning "SQLite3 not found (optional)"
    fi
    
    echo ""
    
    if [ "$all_good" = false ]; then
        print_error "Please install missing dependencies and try again"
        exit 1
    fi
}

# ============================================================================
# SETUP FUNCTIONS
# ============================================================================

setup_backend() {
    echo -e "${BOLD}Setting up backend...${NC}"
    echo ""
    
    cd backend
    
    if [ ! -f "Cargo.toml" ]; then
        print_error "Cargo.toml not found in backend directory"
        exit 1
    fi
    
    print_status "Updating dependencies..."
    cargo update > /dev/null 2>&1
    
    print_status "Building backend ($1 mode)..."
    if [ "$1" = "release" ]; then
        cargo build --release --quiet 2>&1 | grep -v "Compiling" || true
    else
        cargo build --quiet 2>&1 | grep -v "Compiling" || true
    fi
    
    cd ..
    print_success "Backend ready"
    echo ""
}

setup_frontend() {
    echo -e "${BOLD}Setting up frontend...${NC}"
    echo ""
    
    cd frontend
    
    if [ ! -f "package.json" ]; then
        print_error "package.json not found in frontend directory"
        exit 1
    fi
    
    print_status "Installing dependencies..."
    npm install --silent > /dev/null 2>&1
    
    if [ "$1" = "production" ]; then
        print_status "Building for production..."
        npm run build --silent > /dev/null 2>&1
    fi
    
    cd ..
    print_success "Frontend ready"
    echo ""
}

# ============================================================================
# START FUNCTIONS
# ============================================================================

start_backend() {
    print_status "Starting backend server..."
    
    cd backend
    
    export ROCKET_ADDRESS=0.0.0.0
    export ROCKET_PORT=$BACKEND_PORT
    export VAULTLS_API_SECRET="$VAULTLS_API_SECRET"
    
    if [ -n "$VAULTLS_DB_SECRET" ]; then
        export VAULTLS_DB_SECRET="$VAULTLS_DB_SECRET"
    fi
    
    if [ "$1" = "release" ]; then
        nohup cargo run --release > ../backend.log 2>&1 &
    else
        nohup cargo run > ../backend.log 2>&1 &
    fi
    
    BACKEND_PID=$!
    echo $BACKEND_PID > ../backend.pid
    
    # Wait and verify
    sleep 3
    
    if kill -0 $BACKEND_PID 2>/dev/null; then
        print_success "Backend running on port ${BOLD}$BACKEND_PORT${NC} ${DIM}(PID: $BACKEND_PID)${NC}"
    else
        print_error "Backend failed to start"
        cat ../backend.log
        exit 1
    fi
    
    cd ..
}

start_frontend() {
    print_status "Starting frontend server..."
    
    cd frontend
    
    export PORT=$FRONTEND_PORT
    export VITE_API_BASE_URL="http://localhost:$BACKEND_PORT"
    
    if [ "$1" = "production" ]; then
        if command_exists serve || command_exists http-server; then
            nohup npx serve -s dist -l $FRONTEND_PORT > ../frontend.log 2>&1 &
        else
            print_error "Production mode requires 'serve' - Install: ${CYAN}npm install -g serve${NC}"
            exit 1
        fi
    else
        nohup npm run dev -- --host 0.0.0.0 --port $FRONTEND_PORT > ../frontend.log 2>&1 &
    fi
    
    FRONTEND_PID=$!
    echo $FRONTEND_PID > ../frontend.pid
    
    # Wait and verify
    sleep 5
    
    if kill -0 $FRONTEND_PID 2>/dev/null; then
        print_success "Frontend running on port ${BOLD}$FRONTEND_PORT${NC} ${DIM}(PID: $FRONTEND_PID)${NC}"
    else
        print_error "Frontend failed to start"
        cat ../frontend.log
        exit 1
    fi
    
    cd ..
}

# ============================================================================
# STOP FUNCTIONS
# ============================================================================

stop_backend_only() {
    if [ -f "backend.pid" ]; then
        BACKEND_PID=$(cat backend.pid)
        if kill -0 $BACKEND_PID 2>/dev/null; then
            kill $BACKEND_PID
            wait $BACKEND_PID 2>/dev/null
            print_success "Backend stopped"
        fi
        rm -f backend.pid
    else
        print_warning "Backend not running"
    fi
}

stop_frontend_only() {
    if [ -f "frontend.pid" ]; then
        FRONTEND_PID=$(cat frontend.pid)
        if kill -0 $FRONTEND_PID 2>/dev/null; then
            kill $FRONTEND_PID
            wait $FRONTEND_PID 2>/dev/null
            print_success "Frontend stopped"
        fi
        rm -f frontend.pid
    else
        print_warning "Frontend not running"
    fi
}

stop_services() {
    echo -e "${BOLD}Stopping services...${NC}"
    echo ""
    stop_backend_only
    stop_frontend_only
    echo ""
}

# ============================================================================
# STATUS & INFO
# ============================================================================

show_status() {
    print_header
    
    echo -e "${BOLD}Service Status${NC}"
    print_divider
    
    # Backend status
    if [ -f "backend.pid" ]; then
        BACKEND_PID=$(cat backend.pid)
        if kill -0 $BACKEND_PID 2>/dev/null; then
            echo -e "Backend:  ${GREEN}${BOLD}●${NC} Running  ${DIM}(PID: $BACKEND_PID, Port: $BACKEND_PORT)${NC}"
        else
            echo -e "Backend:  ${RED}${BOLD}●${NC} Stopped  ${DIM}(stale PID file)${NC}"
        fi
    else
        echo -e "Backend:  ${DIM}${BOLD}○${NC} Not running${NC}"
    fi
    
    # Frontend status
    if [ -f "frontend.pid" ]; then
        FRONTEND_PID=$(cat frontend.pid)
        if kill -0 $FRONTEND_PID 2>/dev/null; then
            echo -e "Frontend: ${GREEN}${BOLD}●${NC} Running  ${DIM}(PID: $FRONTEND_PID, Port: $FRONTEND_PORT)${NC}"
        else
            echo -e "Frontend: ${RED}${BOLD}●${NC} Stopped  ${DIM}(stale PID file)${NC}"
        fi
    else
        echo -e "Frontend: ${DIM}${BOLD}○${NC} Not running${NC}"
    fi
    
    print_divider
    echo ""
    
    echo -e "${BOLD}Access URLs${NC}"
    print_divider
    echo -e "Frontend: ${CYAN}http://localhost:$FRONTEND_PORT${NC}"
    echo -e "Backend:  ${CYAN}http://localhost:$BACKEND_PORT${NC}"
    echo ""
    
    echo -e "${DIM}View logs: ./vaultls.sh logs${NC}"
    echo ""
}

show_logs() {
    print_header
    
    if [ -f "backend.log" ]; then
        echo -e "${BOLD}Backend Logs${NC} ${DIM}(last 20 lines)${NC}"
        print_divider
        tail -n 20 backend.log
        echo ""
    else
        print_warning "No backend logs found"
    fi
    
    if [ -f "frontend.log" ]; then
        echo -e "${BOLD}Frontend Logs${NC} ${DIM}(last 20 lines)${NC}"
        print_divider
        tail -n 20 frontend.log
        echo ""
    else
        print_warning "No frontend logs found"
    fi
}

show_help() {
    print_header
    
    echo -e "${BOLD}Usage:${NC} $0 ${CYAN}<command>${NC} ${DIM}[options]${NC}"
    echo ""
    
    echo -e "${BOLD}Commands:${NC}"
    print_divider
    echo -e "  ${CYAN}start${NC} [1|2|3]       Start services (interactive or direct)"
    echo -e "                        ${DIM}1=backend, 2=frontend, 3=both${NC}"
    echo -e "  ${CYAN}stop${NC} [1|2|3]        Stop services (interactive or direct)"
    echo -e "  ${CYAN}status${NC}              Show service status"
    echo -e "  ${CYAN}setup${NC}               Setup without starting"
    echo -e "  ${CYAN}logs${NC}                Show recent logs"
    echo -e "  ${CYAN}clean${NC}               Clean build artifacts"
    echo ""
    
    echo -e "${BOLD}Options:${NC}"
    print_divider
    echo -e "  ${CYAN}--release${NC}           Build backend in release mode"
    echo -e "  ${CYAN}--production${NC}        Build frontend for production"
    echo -e "  ${CYAN}--port${NC} ${DIM}<port>${NC}        Set backend port (default: 8000)"
    echo -e "  ${CYAN}--frontend-port${NC} ${DIM}<port>${NC} Set frontend port (default: 4000)"
    echo -e "  ${CYAN}--help${NC}, ${CYAN}-h${NC}          Show this help"
    echo ""
    
    echo -e "${BOLD}Examples:${NC}"
    print_divider
    echo -e "  ${DIM}# Start with interactive menu${NC}"
    echo -e "  $0 start"
    echo ""
    echo -e "  ${DIM}# Start both services directly${NC}"
    echo -e "  $0 start 3"
    echo ""
    echo -e "  ${DIM}# Start backend only in release mode${NC}"
    echo -e "  $0 start 1 --release"
    echo ""
    echo -e "  ${DIM}# Check what's running${NC}"
    echo -e "  $0 status"
    echo ""
}

clean_artifacts() {
    echo -e "${BOLD}Cleaning build artifacts...${NC}"
    echo ""
    
    cd backend
    print_status "Cleaning Rust artifacts..."
    cargo clean
    cd ..
    
    cd frontend
    print_status "Cleaning Node.js artifacts..."
    rm -rf node_modules dist
    cd ..
    
    print_status "Cleaning logs and PID files..."
    rm -f backend.log frontend.log backend.pid frontend.pid
    
    echo ""
    print_success "Cleanup complete"
    echo ""
}

# ============================================================================
# INTERACTIVE MENU
# ============================================================================

show_menu() {
    local prompt="$1"
    local default="$2"
    
    echo -e "${BOLD}$prompt${NC}"
    print_divider
    echo -e "  ${CYAN}1${NC} ${ARROW} Backend only"
    echo -e "  ${CYAN}2${NC} ${ARROW} Frontend only"
    echo -e "  ${CYAN}3${NC} ${ARROW} Both services ${DIM}(recommended)${NC}"
    echo ""
    echo -ne "Choose [${CYAN}$default${NC}]: "
    
    read choice
    choice=${choice:-$default}
    
    echo ""
}

# ============================================================================
# MAIN LOGIC
# ============================================================================

main() {
    local command="start"
    local choice=""
    local backend_mode="debug"
    local frontend_mode="development"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            start|stop|status|setup|logs|clean)
                command="$1"
                shift
                if [[ $# -gt 0 && $1 =~ ^[1-3]$ ]]; then
                    choice="$1"
                    shift
                fi
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
                print_error "Unknown option: ${CYAN}$1${NC}"
                echo ""
                echo -e "Try: ${CYAN}$0 --help${NC}"
                exit 1
                ;;
        esac
    done
    
    # Execute command
    case $command in
        start)
            print_header
            check_requirements
            echo ""
            
            if [ -z "$choice" ]; then
                show_menu "What would you like to start?" "3"
            fi
            
            case $choice in
                1)
                    setup_backend "$backend_mode"
                    start_backend "$backend_mode"
                    echo ""
                    print_success "${ROCKET} Backend is running!"
                    echo -e "  ${DIM}Stop with:${NC} $0 stop 1"
                    ;;
                2)
                    setup_frontend "$frontend_mode"
                    start_frontend "$frontend_mode"
                    echo ""
                    print_success "${ROCKET} Frontend is running!"
                    echo -e "  ${DIM}Stop with:${NC} $0 stop 2"
                    ;;
                3)
                    setup_backend "$backend_mode"
                    setup_frontend "$frontend_mode"
                    start_backend "$backend_mode"
                    start_frontend "$frontend_mode"
                    echo ""
                    print_divider
                    print_success "${ROCKET} VaulTLS is running!"
                    print_divider
                    echo -e "  ${CYAN}${BOLD}→ Frontend: http://localhost:$FRONTEND_PORT${NC}"
                    echo -e "  ${DIM}  Backend:  http://localhost:$BACKEND_PORT${NC}"
                    echo ""
                    echo -e "  ${DIM}Stop with:${NC} $0 stop"
                    ;;
                *)
                    print_error "Invalid choice. Use 1, 2, or 3."
                    exit 1
                    ;;
            esac
            echo ""
            ;;
            
        stop)
            print_header
            
            if [ -z "$choice" ]; then
                show_menu "What would you like to stop?" "3"
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
                    print_error "Invalid choice. Use 1, 2, or 3."
                    exit 1
                    ;;
            esac
            echo ""
            ;;
            
        status)
            show_status
            ;;
            
        setup)
            print_header
            check_requirements
            echo ""
            setup_backend "$backend_mode"
            setup_frontend "$frontend_mode"
            print_success "Setup complete!"
            echo -e "  ${DIM}Start services:${NC} $0 start"
            echo ""
            ;;
            
        logs)
            show_logs
            ;;
            
        clean)
            print_header
            clean_artifacts
            ;;
            
        *)
            print_error "Unknown command: ${CYAN}$command${NC}"
            echo ""
            echo -e "Try: ${CYAN}$0 --help${NC}"
            exit 1
            ;;
    esac
}

# Run the script
main "$@"