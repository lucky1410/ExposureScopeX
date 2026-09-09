#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging Functions
# global verbosity toggle
VERBOSE=false

# Stealth mode — inject randomised delays between tool executions
# Set by --stealth flag in exposurescopex.sh
STEALTH_MODE=false
STEALTH_DELAY_MIN=3   # seconds (minimum inter-tool delay)
STEALTH_DELAY_MAX=15  # seconds (maximum inter-tool delay)

log() {
    local level=$1
    local message=$2
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} [${level}] ${message}" >> "${LOG_FILE}"
}

log_debug() {
    # only print debug messages when VERBOSE is enabled
    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
        log "DEBUG" "$1"
    fi
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
    local install_cmd=${2:-} # Optional instructions only; never evaluated as shell code

    if ! command -v "$tool_name" &> /dev/null; then
        log_warn "Tool '$tool_name' is missing."

        local choice="n"
        if [ "$AUTO_MODE" = true ]; then
            choice="y"
        else
            read -p "Do you want me to install it? (y/n) " choice
        fi

        case "$choice" in 
            y|Y ) 
                log_info "Installing $tool_name..."
                if [ -n "$install_cmd" ]; then
                    log_error "Custom install commands are not executed automatically: $install_cmd"
                    return 1
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

## Additional Validation and Helpers
validate_url() {
    local url=$1
    if [[ "$url" =~ ^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$ ]]; then
        return 0
    else
        return 1
    fi
}

validate_ip() {
    local ip=$1
    # IPv4 check ensuring each octet <=255
    if [[ "$ip" =~ ^([0-9]{1,3})(\.[0-9]{1,3}){3}$ ]]; then
        # verify each octet <=255
        IFS=. read -r o1 o2 o3 o4 <<< "$ip"
        for o in "$o1" "$o2" "$o3" "$o4"; do
            if [ "$o" -gt 255 ] 2>/dev/null; then
                return 1
            fi
        done
        return 0
    fi
    # IPv6 simple check
    if [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]]; then
        return 0
    fi
    return 1
}

install_tool() {
    local tool=$1
    if command -v apt-get &> /dev/null; then
        sudo apt-get update >/dev/null 2>&1
        sudo apt-get install -y "$tool"
        return $?
    elif command -v brew &> /dev/null; then
        brew install "$tool"
        return $?
    elif command -v snap &> /dev/null; then
        sudo snap install "$tool"
        return $?
    else
        log_error "No supported package manager found to install $tool"
        return 1
    fi
}

run_tool() {
    local tool_cmd=$1
    local tool_pkg=${2:-$1}
    shift 2 || true
    local -a tool_args=("$@")
    _TOOL_RUN_SEQUENCE=$(( ${_TOOL_RUN_SEQUENCE:-0} + 1 ))
    local run_id="${tool_cmd}-${$}-${_TOOL_RUN_SEQUENCE}"
    local started_at
    started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local command_text output_log=""
    printf -v command_text '%q ' "$tool_cmd" "${tool_args[@]}"
    command_text=${command_text//$'\t'/ }
    command_text=${command_text//$'\n'/ }
    command_text=$(printf '%s' "$command_text" | sed -E \
        -e 's/(Bearer|token|password|secret|api[_-]?key)[ =:]+[^ ]+/\1=[REDACTED]/Ig')
    if [ -n "${SESSION_DIR:-}" ]; then
        mkdir -p "${SESSION_DIR}/tool_logs"
        output_log="tool_logs/${run_id}.log"
        printf '%s\t%s\trunning\t\t%s\t\t%s\t%s\n' \
            "$run_id" "$tool_cmd" "$started_at" "$command_text" "$output_log" >> "${SESSION_DIR}/tool_runs.tsv"
    fi

    # reset interrupt count at the start of each new tool
    INTERRUPT_COUNT=0

    # check if user requested skip on a previous interrupt
    if [ "$SKIP_THIS_TOOL" = true ]; then
        log_warn "Skipping $tool_cmd due to user interrupt request"
        SKIP_THIS_TOOL=false  # reset for next tool
        return 0
    fi

    if ! command -v "$tool_cmd" &> /dev/null; then
        if [ "$AUTO_MODE" = true ]; then
            log_error "Tool '$tool_cmd' not found and AUTO_MODE enabled"
            if [ -n "${SESSION_DIR:-}" ]; then
                printf '%s\t%s\tfailed\t127\t%s\t%s\t%s\t%s\n' \
                    "$run_id" "$tool_cmd" "$started_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                    "$command_text" "$output_log" >> "${SESSION_DIR}/tool_runs.tsv"
            fi
            return 1
        fi
        read -p "Tool '$tool_cmd' not found. Install it? (y/n) " -r choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            log_info "Attempting to install $tool_pkg..."
            if ! install_tool "$tool_pkg"; then
                log_error "Failed to install $tool_pkg"
                return 1
            fi
        else
            log_warn "Skipping $tool_cmd - some functionality may be unavailable"
            return 1
        fi
    fi

    # Per-tool timeout (seconds); execute_with_timeout is defined in safe_execution.sh
    local tool_timeout
    case "$tool_cmd" in
        nmap|nuclei)            tool_timeout=3600 ;;
        sqlmap|wapiti|amass)    tool_timeout=1800 ;;
        nikto|feroxbuster)      tool_timeout=900  ;;
        subfinder|assetfinder)
            if [ "${MODE:-medium}" = "light" ]; then
                tool_timeout=90
            else
                tool_timeout=300
            fi
            ;;
        *)                      tool_timeout=300  ;;
    esac

    log_debug "Executing (timeout=${tool_timeout}s): $tool_cmd ${tool_args[*]}"
    if [ -n "${SESSION_DIR:-}" ]; then
        execute_with_timeout "$tool_timeout" "$tool_cmd" "${tool_args[@]}" \
            > >(tee -a "${SESSION_DIR}/${output_log}") \
            2> >(tee -a "${SESSION_DIR}/${output_log}" >&2)
    else
        execute_with_timeout "$tool_timeout" "$tool_cmd" "${tool_args[@]}"
    fi
    local rc=$?
    if   [ $rc -eq 124 ]; then log_warn  "Tool '$tool_cmd' timed out after ${tool_timeout}s"
    elif [ $rc -ne 0 ];   then log_error "Tool '$tool_cmd' failed with exit code $rc"
    fi

    if [ -n "${SESSION_DIR:-}" ]; then
        local run_status="completed"
        [ $rc -eq 124 ] && run_status="timed_out"
        [ $rc -ne 0 ] && [ $rc -ne 124 ] && run_status="failed"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$run_id" "$tool_cmd" "$run_status" "$rc" "$started_at" \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$command_text" "$output_log" >> "${SESSION_DIR}/tool_runs.tsv"
    fi

    # Stealth mode: randomised inter-tool delay to reduce detection fingerprint
    if [ "${STEALTH_MODE:-false}" = true ]; then
        local delay=$(( STEALTH_DELAY_MIN + RANDOM % (STEALTH_DELAY_MAX - STEALTH_DELAY_MIN + 1) ))
        log_debug "[stealth] Sleeping ${delay}s before next tool..."
        sleep "$delay"
    fi

    return $rc
}

create_temp_dir() {
    local tmp
    tmp=$(mktemp -d 2>/dev/null || mktemp -d -t exposurescopex)
    chmod 700 "$tmp"
    echo "$tmp"
}

sanitize_filename() {
    local filename=$1
    echo "$filename" | sed 's/[^a-zA-Z0-9._-]/_/g'
}

# IPv4 CIDR notation validation (e.g. 192.168.1.0/24)
validate_cidr() {
    local cidr=$1
    if [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
        local net="${cidr%/*}"
        validate_ip "$net" && return 0
    fi
    return 1
}

# Detect the type of a target string.
# Outputs one of: url | cidr | ip | domain | file | unknown
detect_target_type() {
    local t=$1
    if validate_url "$t"    2>/dev/null; then echo "url"
    elif validate_cidr "$t" 2>/dev/null; then echo "cidr"
    elif validate_ip "$t"   2>/dev/null; then echo "ip"
    elif validate_domain "$t" 2>/dev/null; then echo "domain"
    elif [ -f "$t" ];                    then echo "file"
    else echo "unknown"; fi
}

# handle_interrupt is defined in error_handling.sh (interactive skip/quit prompt).
# Do not redefine it here.
