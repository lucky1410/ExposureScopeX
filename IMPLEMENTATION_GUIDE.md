# ExposureScopeX - Implementation Guide for Recommended Fixes

> Historical v1 remediation guide. Current instructions are in `webapp/docs/OPERATIONS.md` and `webapp/docs/ARCHITECTURE.md`.

This document provides code examples and step-by-step instructions to implement the recommendations from the comprehensive review.

---

## Priority 1: Critical Security Fixes

### Fix 1.1: Secure Configuration Handling

**Create** `config/exposurescopex.conf.template`:
```bash
#!/bin/bash
# ExposureScopeX Global Configuration Template
# Copy this file to exposurescopex.conf and fill in your values
# DO NOT commit exposurescopex.conf to version control

# Directories (auto-detected, usually no need to change)
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${INSTALL_DIR}/results"
MODULES_DIR="${INSTALL_DIR}/modules"
CONFIG_DIR="${INSTALL_DIR}/config"
LOG_FILE="${INSTALL_DIR}/exposurescopex.log"

# Tools Configuration
CMD_NMAP="nmap"
CMD_NUCLEI="nuclei"
CMD_SUBFINDER="subfinder"
CMD_ASSETFINDER="assetfinder"
# ... etc ...

# API Keys - Use environment variables for sensitive data
# Example: export SHODAN_API_KEY="your_key" before running
SHODAN_API_KEY="${SHODAN_API_KEY:-}"
CENSYS_API_ID="${CENSYS_API_ID:-}"
CENSYS_API_SECRET="${CENSYS_API_SECRET:-}"
VIRUSTOTAL_API_KEY="${VIRUSTOTAL_API_KEY:-}"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
TEAMS_WEBHOOK_URL="${TEAMS_WEBHOOK_URL:-}"
SPLUNK_HEC_URL="${SPLUNK_HEC_URL:-}"
SPLUNK_HEC_TOKEN="${SPLUNK_HEC_TOKEN:-}"

# Default Settings
SCAN_SPEED="medium"
THREADS=50
USER_AGENT="ExposureScopeX-Framework/1.0"
```

**Create** `.gitignore`:
```
# Configuration with secrets
config/exposurescopex.conf
!config/exposurescopex.conf.template

# Results
results/
*.log

# Environment files
.env
.env.local

# OS files
.DS_Store
.vscode/
*.swp

# Python cache (if Python added later)
__pycache__/
*.pyc
```

**Update** initialization in `exposurescopex.sh`:
```bash
# At the top, after sourcing config:

# Initialize config from template if missing
if [ ! -f "${SCRIPT_DIR}/config/exposurescopex.conf" ]; then
    if [ -f "${SCRIPT_DIR}/config/exposurescopex.conf.template" ]; then
        log_warn "Config file not found. Creating from template..."
        cp "${SCRIPT_DIR}/config/exposurescopex.conf.template" \
           "${SCRIPT_DIR}/config/exposurescopex.conf"
        log_warn "Please edit config/exposurescopex.conf with your API keys"
        log_warn "DO NOT commit this file to version control"
    else
        log_fatal "Config template not found"
    fi
fi

# Validate that config exists
if [ ! -f "${SCRIPT_DIR}/config/exposurescopex.conf" ]; then
    log_fatal "Configuration file not found at config/exposurescopex.conf"
fi

source "${SCRIPT_DIR}/config/exposurescopex.conf"
```

---

### Fix 1.2: Prevent Command Injection

**Create** `modules/safe_execution.sh`:
```bash
#!/bin/bash

##
# Execute a command safely with proper argument handling
# Prevents shell injection and quoting issues
#
# Arguments: command [arg1] [arg2] ...
# Returns: Command exit code
##
safe_execute() {
    local cmd=$1
    shift
    local args=("$@")

    if [ -z "$cmd" ]; then
        log_error "safe_execute: No command specified"
        return 1
    fi

    # Check command exists
    if ! command -v "$cmd" &> /dev/null; then
        log_error "Command not found: $cmd"
        return 127
    fi

    # Execute with proper argument passing
    "$cmd" "${args[@]}"
    return $?
}

##
# Execute nmap with safety checks
##
execute_nmap() {
    local nmap_flags=$1
    shift
    local targets=("$@")

    local -a cmd_args=()

    # Parse flags safely
    for flag in $nmap_flags; do
        cmd_args+=("$flag")
    done

    # Add targets
    cmd_args+=("${targets[@]}")

    safe_execute "nmap" "${cmd_args[@]}"
}

##
# Execute tool with timeout
##
execute_with_timeout() {
    local timeout_sec=$1
    local tool=$2
    shift 2
    local args=("$@")

    if ! command -v timeout &> /dev/null; then
        log_warn "timeout command not found, running without timeout"
        safe_execute "$tool" "${args[@]}"
        return $?
    fi

    timeout "$timeout_sec" "$tool" "${args[@]}"
    local exit_code=$?

    if [ $exit_code -eq 124 ]; then
        log_error "Command '$tool' timed out after ${timeout_sec}s"
        return 1
    fi

    return $exit_code
}
```

**Update** `modules/port_scan.sh`:
```bash
#!/bin/bash

source "${SCRIPT_DIR}/modules/safe_execution.sh"

run_port_scan() {
    local target=$1
    local output_dir=$2
    local nmap_output="${output_dir}/nmap_scan.txt"
    local nmap_xml="${output_dir}/nmap_scan.xml"

    log_info "Starting Port Scanning..."

    ensure_tool_installed "nmap" || return 1

    local nmap_args=""

    case "$SCAN_SPEED" in
        light)
            log_info "Mode: Light (Top 100 ports, fast)"
            nmap_args="-F -T4 --open"
            ;;
        medium)
            log_info "Mode: Medium (Top 1000 ports, service detection)"
            nmap_args="-sV -sC -T4 --top-ports 1000 --open"
            ;;
        aggressive)
            log_info "Mode: Aggressive (All ports, OS detection, scripts)"
            nmap_args="-p- -sV -sC -O -T4 --open"
            ;;
        *)
            nmap_args="-sV -T4 --top-ports 1000"
            ;;
    esac

    # Build target list
    local -a nmap_targets=()
    if [ -f "$target" ]; then
        mapfile -t nmap_targets < "$target"
    else
        nmap_targets=("$target")
    fi

    # Execute nmap safely
    if ! execute_nmap "$nmap_args" \
            -oN "$nmap_output" \
            -oX "$nmap_xml" \
            "${nmap_targets[@]}"; then
        log_error "Nmap scan failed"
        return 1
    fi

    log_success "Port scanning complete."
    log_info "Results saved to: $nmap_output"
    return 0
}
```

---

### Fix 1.3: Input Validation Framework

**Add to** `modules/utils.sh`:
```bash
##
# Validate domain format
# Args: domain string
# Returns: 0 if valid, 1 if invalid
##
validate_domain() {
    local domain=$1

    # Remove trailing dot
    domain="${domain%.}"

    # Check format using regex
    if [[ ! "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        return 1
    fi

    # Check length (max 253 chars per RFC 1035)
    if [ ${#domain} -gt 253 ]; then
        return 1
    fi

    return 0
}

##
# Validate URL format
##
validate_url() {
    local url=$1

    # Basic URL validation
    if [[ ! "$url" =~ ^https?://[a-zA-Z0-9.-]+(:[0-9]+)?(/.*)?$ ]]; then
        return 1
    fi

    return 0
}

##
# Validate IP address (IPv4 or IPv6)
##
validate_ip() {
    local ip=$1

    # IPv4
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    fi

    # IPv6 (simple check)
    if [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]]; then
        return 0
    fi

    return 1
}

##
# Validate file exists and is readable
##
validate_file() {
    local file=$1

    if [ ! -f "$file" ]; then
        log_error "File not found: $file"
        return 1
    fi

    if [ ! -r "$file" ]; then
        log_error "File not readable: $file"
        return 1
    fi

    return 0
}

##
# Sanitize output filename
##
sanitize_filename() {
    local filename=$1
    # Remove/replace dangerous characters
    echo "$filename" | sed 's/[^a-zA-Z0-9._-]/_/g'
}
```

**Use in** `exposurescopex.sh` main function:
```bash
main() {
    # ... existing code ...

    # Validate inputs
    if [ -n "$TARGET_DOMAIN" ]; then
        if ! validate_domain "$TARGET_DOMAIN"; then
            log_fatal "Invalid domain format: $TARGET_DOMAIN"
        fi
        log_info "Target: $TARGET_DOMAIN"
    fi

    if [ -n "$TARGET_FILE" ]; then
        if ! validate_file "$TARGET_FILE"; then
            log_fatal "Target file validation failed"
        fi
        log_info "Target List: $TARGET_FILE"
    fi

    # ... rest of main ...
}
```

---

## Priority 2: Centralized Error Handling

### Fix 2.1: Cleanup and Signal Handling

**Create** `modules/error_handling.sh`:
```bash
#!/bin/bash

# Global state tracking
readonly CLEANUP_FILES=()
readonly BACKGROUND_JOBS=()

##
# Register a file for cleanup on exit
##
register_cleanup() {
    local file=$1
    CLEANUP_FILES+=("$file")
}

##
# Perform cleanup on exit
##
cleanup_on_exit() {
    local exit_code=$?

    log_info "Performing cleanup..."

    # Kill background jobs
    if [ ${#BACKGROUND_JOBS[@]} -gt 0 ]; then
        for job_pid in "${BACKGROUND_JOBS[@]}"; do
            if kill -0 "$job_pid" 2>/dev/null; then
                log_info "Terminating background job: $job_pid"
                kill -TERM "$job_pid" 2>/dev/null
                sleep 1
                kill -KILL "$job_pid" 2>/dev/null || true
            fi
        done
    fi

    # Clean up temp files
    for file in "${CLEANUP_FILES[@]}"; do
        if [ -e "$file" ]; then
            rm -rf "$file" 2>/dev/null || true
        fi
    done

    # Final status
    if [ $exit_code -eq 0 ]; then
        log_success "Session completed successfully"
    else
        log_error "Session terminated with exit code $exit_code"
    fi

    exit $exit_code
}

##
# Handle interrupt signals (Ctrl+C)
##
handle_interrupt() {
    echo ""
    log_warn "Caught interrupt signal. Cleaning up..."
    exit 130
}

##
# Setup signal handlers
##
setup_signal_handlers() {
    trap cleanup_on_exit EXIT
    trap handle_interrupt SIGINT SIGTERM
}
```

**Update** `exposurescopex.sh`:
```bash
#!/bin/bash

# ... existing sources ...
source "${SCRIPT_DIR}/modules/error_handling.sh"

# ... rest of script ...

main() {
    # Setup signal handlers at the very beginning
    setup_signal_handlers

    # ... rest of main function ...
}

# Run main
main "$@"
```

---

## Priority 3: Unified Tool Execution

### Fix 3.1: Standardized Tool Wrapper

**Add to** `modules/utils.sh`:
```bash
##
# Unified tool execution wrapper
# Handles installation, checking, and error reporting
#
# Args:
#   $1 - Tool name (command)
#   $2 - Tool package name (if different from command)
#   $3... - Arguments to pass to tool
#
# Returns:
#   Tool's exit code
##
run_tool() {
    local tool_cmd=$1
    local tool_pkg=${2:-$1}  # Use command name as package if not specified
    shift 2  # Remove tool_cmd and tool_pkg
    local -a tool_args=("$@")

    # Check if tool exists
    if ! command -v "$tool_cmd" &> /dev/null; then
        if [ "$AUTO_MODE" = true ]; then
            log_error "Tool '$tool_cmd' not found and AUTO_MODE enabled"
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

    # Execute tool with arguments
    log_info "Executing: $tool_cmd ${tool_args[*]}"
    if "$tool_cmd" "${tool_args[@]}"; then
        return 0
    else
        local exit_code=$?
        log_error "Tool '$tool_cmd' failed with exit code $exit_code"
        return $exit_code
    fi
}

##
# Install system package
##
install_tool() {
    local tool=$1

    if command -v apt-get &> /dev/null; then
        sudo apt-get update >/dev/null 2>&1
        sudo apt-get install -y "$tool" >/dev/null 2>&1
    elif command -v brew &> /dev/null; then
        brew install "$tool" >/dev/null 2>&1
    elif command -v snap &> /dev/null; then
        sudo snap install "$tool" >/dev/null 2>&1
    else
        log_error "No supported package manager found (apt/brew/snap)"
        return 1
    fi

    if command -v "$tool" &> /dev/null; then
        log_success "$tool installed successfully"
        return 0
    else
        log_error "Failed to install $tool"
        return 1
    fi
}
```

**Usage examples:**
```bash
# In enumeration.sh:
run_tool "subfinder" "subfinder" -d "$domain" -silent >> "$temp_file" || \
    log_warn "Subfinder failed"

run_tool "assetfinder" "assetfinder" --subs-only "$domain" >> "$temp_file" || \
    log_warn "Assetfinder failed"

# In port_scan.sh:
run_tool "nmap" "nmap" $nmap_args "${nmap_targets[@]}" \
    -oN "$nmap_output" -oX "$nmap_xml" || \
    log_fatal "Nmap scan failed"
```

---

## Priority 4: Improved Reporting

### Fix 4.1: HTML Safe Output

**Update** `modules/reporting.sh`:
```bash
#!/bin/bash

##
# HTML-escape special characters
##
html_escape() {
    local str="$1"
    # Order matters - escape & first
    str="${str//&/&amp;}"
    str="${str//</&lt;}"
    str="${str//>/&gt;}"
    str="${str//\"/&quot;}"
    str="${str//\'/&#39;}"
    echo "$str"
}

##
# Generate vulnerability summary with counts
##
generate_vuln_summary() {
    local session_dir=$1
    local nuclei_file="${session_dir}/nuclei_results.txt"

    if [ ! -f "$nuclei_file" ]; then
        return
    fi

    local critical=$(grep -c "\[critical\]" "$nuclei_file" || echo 0)
    local high=$(grep -c "\[high\]" "$nuclei_file" || echo 0)
    local medium=$(grep -c "\[medium\]" "$nuclei_file" || echo 0)
    local low=$(grep -c "\[low\]" "$nuclei_file" || echo 0)
    local info=$(grep -c "\[info\]" "$nuclei_file" || echo 0)

    echo "## Vulnerability Summary"
    echo ""
    echo "| Severity | Count |"
    echo "|----------|-------|"
    echo "| Critical | $critical |"
    echo "| High     | $high |"
    echo "| Medium   | $medium |"
    echo "| Low      | $low |"
    echo "| Info     | $info |"
    echo ""
}

##
# Parse and format nmap results
##
format_nmap_results() {
    local nmap_file=$1

    if [ ! -f "$nmap_file" ]; then
        return
    fi

    echo "## Open Ports and Services"
    echo ""
    echo "| Host | Port | State | Service | Version |"
    echo "|------|------|-------|---------|---------|"

    grep "open" "$nmap_file" | while read -r line; do
        local host=$(echo "$line" | awk '{print $NF}')
        local port=$(echo "$line" | awk '{print $1}')
        local state=$(echo "$line" | awk '{print $2}')
        local service=$(echo "$line" | awk '{print $3}')
        local version=$(echo "$line" | cut -d' ' -f4-)

        version=$(html_escape "$version")
        echo "| $host | $port | $state | $service | $version |"
    done
}

##
# Main report generation
##
generate_report() {
    local session_dir=$1
    local report_md="${session_dir}/report.md"
    local report_pdf="${session_dir}/report.pdf"

    log_info "Generating Report..."

    {
        echo "# ExposureScopeX Report"
        echo ""
        echo "**Generated:** $(date)"
        echo ""

        echo "## Scan Information"
        echo "- **Session Directory:** $session_dir"
        echo "- **Framework Version:** 1.0.0"
        echo ""

        # Vulnerability summary
        generate_vuln_summary "$session_dir"

        # Subdomains
        if [ -f "${session_dir}/subdomains.txt" ]; then
            echo "## Discovered Subdomains"
            local count=$(wc -l < "${session_dir}/subdomains.txt")
            echo "Found $count unique subdomains:"
            echo ""
            echo '```'
            cat "${session_dir}/subdomains.txt"
            echo '```'
            echo ""
        fi

        # Port scan results
        if [ -f "${session_dir}/nmap_scan.txt" ]; then
            format_nmap_results "${session_dir}/nmap_scan.txt"
            echo ""
        fi

        # Vulnerabilities (safe output)
        if [ -f "${session_dir}/nuclei_results.txt" ]; then
            echo "## Detailed Vulnerabilities"
            echo ""
            while IFS= read -r line; do
                local escaped=$(html_escape "$line")
                if [[ "$line" == *"[critical]"* ]]; then
                    echo "**🔴 CRITICAL:** $escaped"
                elif [[ "$line" == *"[high]"* ]]; then
                    echo "**🟠 HIGH:** $escaped"
                elif [[ "$line" == *"[medium]"* ]]; then
                    echo "**🟡 MEDIUM:** $escaped"
                elif [[ "$line" == *"[low]"* ]]; then
                    echo "**🔵 LOW:** $escaped"
                elif [[ "$line" == *"[info]"* ]]; then
                    echo "**ℹ️ INFO:** $escaped"
                fi
                echo ""
            done < "${session_dir}/nuclei_results.txt"
        fi

        # OSINT findings
        if [ -f "${session_dir}/osint_results.txt" ]; then
            echo "## OSINT Findings"
            echo ""
            echo '```'
            cat "${session_dir}/osint_results.txt"
            echo '```'
            echo ""
        fi

        # Recommendations
        echo "## Recommendations"
        echo ""
        echo "1. **Immediate Actions:**"
        echo "   - Review and remediate all CRITICAL vulnerabilities"
        echo "   - Close unnecessary open ports"
        echo "   - Rotate any exposed credentials"
        echo ""
        echo "2. **Short Term (30 days):**"
        echo "   - Patch all HIGH severity vulnerabilities"
        echo "   - Review external-facing services"
        echo "   - Audit cloud misconfigurations"
        echo ""
        echo "3. **Long Term (90 days):**"
        echo "   - Implement Web Application Firewall (WAF)"
        echo "   - Deploy continuous vulnerability scanning"
        echo "   - Establish incident response procedures"
        echo ""

        # Footer
        echo "---"
        echo "*Report generated by ExposureScopeX Framework*"

    } > "$report_md"

    log_success "Markdown report generated: $report_md"

    # PDF conversion
    if command -v pandoc &> /dev/null; then
        log_info "Converting to PDF..."
        local css_file="${CONFIG_DIR}/report.css"
        local pandoc_opts=""

        if [ -f "$css_file" ]; then
            pandoc_opts="--css $css_file"
        fi

        if pandoc "$report_md" -o "$report_pdf" $pandoc_opts 2>/dev/null; then
            log_success "PDF report generated: $report_pdf"
        else
            log_warn "PDF generation failed - markdown available"
        fi
    else
        log_warn "Pandoc not found - skipping PDF generation"
    fi

    return 0
}
```

---

## Testing Your Implementation

Create `tests/run_tests.sh`:
```bash
#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${SCRIPT_DIR}/modules/utils.sh"

test_count=0
pass_count=0
fail_count=0

run_test() {
    local test_name=$1
    local test_func=$2

    ((test_count++))
    echo -n "[$test_count] $test_name ... "

    if $test_func; then
        echo "✓ PASS"
        ((pass_count++))
    else
        echo "✗ FAIL"
        ((fail_count++))
    fi
}

test_domain_validation() {
    validate_domain "example.com" || return 1
    validate_domain "sub.example.co.uk" || return 1
    ! validate_domain "invalid" || return 1
    ! validate_domain "." || return 1
    return 0
}

test_url_validation() {
    validate_url "https://example.com" || return 1
    validate_url "http://example.com:8080" || return 1
    ! validate_url "not-a-url" || return 1
    return 0
}

test_ip_validation() {
    validate_ip "192.168.1.1" || return 1
    validate_ip "127.0.0.1" || return 1
    ! validate_ip "256.256.256.256" || return 1
    return 0
}

test_file_validation() {
    local tmpfile=$(mktemp)
    validate_file "$tmpfile" || return 1
    ! validate_file "/nonexistent/file" || return 1
    rm "$tmpfile"
    return 0
}

# Run all tests
run_test "Domain validation" test_domain_validation
run_test "URL validation" test_url_validation
run_test "IP validation" test_ip_validation
run_test "File validation" test_file_validation

# Summary
echo ""
echo "========================"
echo "Tests Run: $test_count"
echo "Passed:    $pass_count"
echo "Failed:    $fail_count"
echo "========================"

[ $fail_count -eq 0 ]
```

Run tests with:
```bash
chmod +x tests/run_tests.sh
./tests/run_tests.sh
```

---

## Next Steps

1. **Implement Priority 1 fixes first** - These are security-critical
2. **Test each module after fixes** - Run individual modules to verify
3. **Update documentation** - Document any behavior changes
4. **Create changelog** - Track all modifications
5. **Version bump** - Move from 1.0.0→1.0.1 after fixes

---

## Quick Implementation Checklist

- [ ] Create `config/exposurescopex.conf.template`
- [ ] Create and update `.gitignore`
- [ ] Add `modules/safe_execution.sh`
- [ ] Add `modules/error_handling.sh`
- [ ] Update `modules/utils.sh` with validation functions
- [ ] Update main script to use signal handlers
- [ ] Refactor modules to use `run_tool()` wrapper
- [ ] Update reporting with HTML escaping
- [ ] Add `tests/run_tests.sh`
- [ ] Test all changes in non-production environment
- [ ] Commit with meaningful messages
- [ ] Tag release (v1.0.1-security-patch)
