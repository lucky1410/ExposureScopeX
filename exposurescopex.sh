#!/bin/bash

# ExposureScopeX - Continuous Attack Surface & Exposure Monitoring Framework
# Author: Lakshmikanth
# Version: 1.0.0

# Source Configuration and Utils
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config/exposurescopex.conf"
source "${SCRIPT_DIR}/modules/utils.sh"
source "${SCRIPT_DIR}/modules/enumeration.sh"
source "${SCRIPT_DIR}/modules/port_scan.sh"
source "${SCRIPT_DIR}/modules/vuln_scan.sh"
source "${SCRIPT_DIR}/modules/web_test.sh"
source "${SCRIPT_DIR}/modules/exploitation.sh"
source "${SCRIPT_DIR}/modules/osint.sh"
source "${SCRIPT_DIR}/modules/cloud.sh"
source "${SCRIPT_DIR}/modules/reporting.sh"
source "${SCRIPT_DIR}/modules/integrations.sh"

# Initialize variables
TARGET_DOMAIN=""
TARGET_FILE=""
RUN_ENUM=false
RUN_SCAN=false
RUN_EXPLOIT=false
RUN_CLOUD=false
RUN_REPORT=false
OUTPUT_FILE=""
MODE="medium"
AUTO_MODE=false
SLACK_NOTIFY=false
TEAMS_NOTIFY=false
SIEM_NOTIFY=false

# Help Menu
show_help() {
    print_banner
    echo "Usage: ./exposurescopex.sh [options]"
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN       Target single domain"
    echo "  -f, --file FILE           File containing list of domains"
    echo "  -e, --enum                Run enumeration (subdomains, assets)"
    echo "  -s, --scan                Run vulnerability scanning"
    echo "  -x, --exploit             Enable exploitation (CAUTION)"
    echo "  -c, --cloud               Run cloud misconfiguration detection"
    echo "  -o, --output FILE         Custom output file prefix"
    echo "  -m, --mode LEVEL          Scan mode: light, medium, aggressive (default: medium)"
    echo "  --slack                   Send notifications to Slack"
    echo "  --teams                   Send notifications to Teams"
    echo "  --siem                    Send logs to SIEM"
    echo "  --auto                    Non-interactive mode (auto-yes)"
    echo "  -r, --report              Generate MD & PDF report"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./exposurescopex.sh -d example.com -e -s -r"
    echo "  ./exposurescopex.sh -f targets.txt --auto --slack"
    echo ""
}

# Parse Arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -d|--domain) TARGET_DOMAIN="$2"; shift ;;
        -f|--file) TARGET_FILE="$2"; shift ;;
        -e|--enum) RUN_ENUM=true ;;
        -s|--scan) RUN_SCAN=true ;;
        -x|--exploit) RUN_EXPLOIT=true ;;
        -c|--cloud) RUN_CLOUD=true ;;
        -o|--output) OUTPUT_FILE="$2"; shift ;;
        -m|--mode) MODE="$2"; shift ;;
        --slack) SLACK_NOTIFY=true ;;
        --teams) TEAMS_NOTIFY=true ;;
        --siem) SIEM_NOTIFY=true ;;
        --auto) AUTO_MODE=true ;;
        -r|--report) RUN_REPORT=true ;;
        -h|--help) show_help; exit 0 ;;
        *) log_error "Unknown parameter passed: $1"; show_help; exit 1 ;;
    esac
    shift
done

# Main Execution
main() {
    print_banner
    log_info "Starting ExposureScopeX Framework..."

    # Validation
    if [ -z "$TARGET_DOMAIN" ] && [ -z "$TARGET_FILE" ]; then
        log_error "No target specified. Use -d or -f."
        show_help
        exit 1
    fi

    if [ -n "$TARGET_DOMAIN" ]; then
        if ! validate_domain "$TARGET_DOMAIN"; then
            log_fatal "Invalid domain format: $TARGET_DOMAIN"
        fi
        log_info "Target: $TARGET_DOMAIN"
    fi

    if [ -n "$TARGET_FILE" ]; then
        if ! validate_file "$TARGET_FILE"; then
            log_fatal "Target file not found: $TARGET_FILE"
        fi
        log_info "Target List: $TARGET_FILE"
    fi

    # Create Results Directory
    if [ -n "$TARGET_DOMAIN" ]; then
        SESSION_DIR="${RESULTS_DIR}/${TARGET_DOMAIN}_$(date +%Y%m%d_%H%M%S)"
    else
        SESSION_DIR="${RESULTS_DIR}/batch_$(date +%Y%m%d_%H%M%S)"
    fi
    mkdir -p "$SESSION_DIR"
    log_info "Results will be saved to: $SESSION_DIR"

    # Dependency Checks (Basic)
    check_dependency "curl"
    check_dependency "jq"

    # Workflow Logic
    
    # 1. Enumeration
    if [ "$RUN_ENUM" = true ]; then
        run_enumeration "$TARGET_DOMAIN" "$SESSION_DIR"
    elif [ "$RUN_SCAN" = true ] && [ -n "$TARGET_DOMAIN" ]; then
        # Case 1: Scan selected but no enum.
        if [ "$AUTO_MODE" = false ]; then
            read -p "Enumeration skipped. Do you want to run it first? (y/n) " choice
            if [[ "$choice" =~ ^[Yy]$ ]]; then
                run_enumeration "$TARGET_DOMAIN" "$SESSION_DIR"
            fi
        fi
    fi

    # 2. Port Scanning
    if [ "$RUN_SCAN" = true ]; then
        if [ -n "$TARGET_FILE" ]; then
            run_port_scan "$TARGET_FILE" "$SESSION_DIR"
        else
            run_port_scan "$TARGET_DOMAIN" "$SESSION_DIR"
        fi
    fi

    # 3. Vulnerability Scanning
    if [ "$RUN_SCAN" = true ]; then
        if [ -n "$TARGET_FILE" ]; then
            run_vuln_scan "$TARGET_FILE" "$SESSION_DIR"
            run_web_test "$TARGET_FILE" "$SESSION_DIR"
        else
            run_vuln_scan "$TARGET_DOMAIN" "$SESSION_DIR"
            run_web_test "$TARGET_DOMAIN" "$SESSION_DIR"
        fi
    fi

    # 4. Cloud Misconfiguration
    if [ "$RUN_CLOUD" = true ]; then
        if [ -n "$TARGET_DOMAIN" ]; then
            run_cloud_scan "$TARGET_DOMAIN" "$SESSION_DIR"
        else
            log_warn "Cloud scan requires a domain target."
        fi
    fi

    # 5. OSINT
    if [ -n "$TARGET_DOMAIN" ]; then
        run_osint "$TARGET_DOMAIN" "$SESSION_DIR"
    fi

    # 6. Exploitation
    if [ "$RUN_EXPLOIT" = true ]; then
        if [ -n "$TARGET_DOMAIN" ]; then
            run_exploitation "$TARGET_DOMAIN" "$SESSION_DIR"
        fi
    fi

    # 7. Reporting
    if [ "$RUN_REPORT" = true ]; then
        generate_report "$SESSION_DIR"
        send_slack_notification "ExposureScopeX Scan Completed for $TARGET_DOMAIN" "${SESSION_DIR}/report.pdf"
        send_teams_notification "ExposureScopeX Scan Completed for $TARGET_DOMAIN"
    elif [ "$RUN_SCAN" = true ] && [ "$RUN_REPORT" = false ]; then
         if [ "$AUTO_MODE" = false ]; then
            read -p "Scan finished. Generate report? (y/n) " choice
             if [[ "$choice" =~ ^[Yy]$ ]]; then
                generate_report "$SESSION_DIR"
                send_slack_notification "ExposureScopeX Scan Completed for $TARGET_DOMAIN" "${SESSION_DIR}/report.pdf"
            fi
        fi
    fi

    log_success "ExposureScopeX Session Completed."
}

# Trap for cleanup
trap 'log_info "Exiting..."; exit 0' SIGINT SIGTERM

# Run Main
main
