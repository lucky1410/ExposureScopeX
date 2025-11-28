#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging Functions
log() {
    local level=$1
    local message=$2
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} [${level}] ${message}" >> "${LOG_FILE}"
}

log_info() {
    echo -e "${BLUE}[*]${NC} $1"
    log "INFO" "$1"
}

log_success() {
    echo -e "${GREEN}[+]${NC} $1"
    log "SUCCESS" "$1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
    log "WARN" "$1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
    log "ERROR" "$1"
}

log_fatal() {
    echo -e "${RED}[FATAL]${NC} $1"
    log "FATAL" "$1"
    exit 1
}

# Banner
print_banner() {
    if [ -f "${CONFIG_DIR}/banner.txt" ]; then
        cat "${CONFIG_DIR}/banner.txt"
        echo ""
    else
        echo "ExposureScopeX Framework"
    fi
}

# Dependency Check
check_dependency() {
    local tool_name=$1
    local install_cmd=$2 # Optional custom install command

    if ! command -v "$tool_name" &> /dev/null; then
        log_warn "Tool '$tool_name' is missing."
        read -p "Do you want me to install it? (y/n) " choice
        case "$choice" in 
            y|Y ) 
                log_info "Installing $tool_name..."
                if [ -n "$install_cmd" ]; then
                    eval "$install_cmd"
                elif command -v apt-get &> /dev/null; then
                    # Debian/Ubuntu/Kali
                    sudo apt-get update && sudo apt-get install -y "$tool_name"
                elif command -v brew &> /dev/null; then
                    # macOS (Homebrew)
                    brew install "$tool_name"
                else
                    log_error "No supported package manager found (apt/brew). Install $tool_name manually."
                    return 1
                fi
                
                if command -v "$tool_name" &> /dev/null; then
                    log_success "$tool_name installed successfully."
                else
                    log_error "Failed to install $tool_name. Please install it manually."
                    return 1
                fi
                ;;
            * ) 
                log_warn "Skipping $tool_name. Some features may not work."
                return 1
                ;;
        esac
    else
        log "INFO" "Tool '$tool_name' found."
    fi
    return 0
}

# Input Validation
validate_domain() {
    local domain=$1
    if [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

validate_file() {
    local file=$1
    if [ -f "$file" ]; then
        return 0
    else
        return 1
    fi
}
