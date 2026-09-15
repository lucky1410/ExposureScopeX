#!/bin/bash

# ExposureScopeX - Continuous Attack Surface & Exposure Monitoring Framework
# Author: Lakshmikanth
# Version: 2.2.0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ──────────────────────────────────────────────────────────────────────────────
# Bootstrap configuration
# ──────────────────────────────────────────────────────────────────────────────
CONFIG_FILE="${EXPOSURESCOPEX_CONFIG_FILE:-${SCRIPT_DIR}/config/exposurescopex.conf}"
if [ ! -f "$CONFIG_FILE" ]; then
    if [ -f "${SCRIPT_DIR}/config/exposurescopex.conf.template" ]; then
        if [ -w "${SCRIPT_DIR}/config" ]; then
            echo "Config not found - creating from template: config/exposurescopex.conf"
            cp "${SCRIPT_DIR}/config/exposurescopex.conf.template" "$CONFIG_FILE"
            echo "Edit config/exposurescopex.conf to add API keys (do not commit this file)."
        else
            CONFIG_FILE="${SCRIPT_DIR}/config/exposurescopex.conf.template"
            echo "Config directory is read-only - using the environment-backed template."
        fi
    else
        echo "Config template missing: config/exposurescopex.conf.template"
    fi
fi

if [ -f "$CONFIG_FILE" ]; then
    # The template reads secrets and runtime paths from environment variables.
    source "$CONFIG_FILE"
else
    echo "No ExposureScopeX configuration is available." >&2
    exit 2
fi

# Core utilities load first (other modules depend on log_* and validate_*)
source "${SCRIPT_DIR}/modules/utils.sh"
source "${SCRIPT_DIR}/modules/safe_execution.sh"
source "${SCRIPT_DIR}/modules/error_handling.sh"

setup_signal_handlers

# Feature modules
source "${SCRIPT_DIR}/modules/scope.sh"
source "${SCRIPT_DIR}/modules/continuous.sh"
source "${SCRIPT_DIR}/modules/passive.sh"
source "${SCRIPT_DIR}/modules/enumeration.sh"
source "${SCRIPT_DIR}/modules/dns_recon.sh"
source "${SCRIPT_DIR}/modules/port_scan.sh"
source "${SCRIPT_DIR}/modules/ssl_check.sh"
source "${SCRIPT_DIR}/modules/crawler.sh"
source "${SCRIPT_DIR}/modules/web_auth.sh"
source "${SCRIPT_DIR}/modules/safe_web_validation.sh"
source "${SCRIPT_DIR}/modules/web_test.sh"
source "${SCRIPT_DIR}/modules/screenshot.sh"
source "${SCRIPT_DIR}/modules/api_security.sh"
source "${SCRIPT_DIR}/modules/vuln_scan.sh"
source "${SCRIPT_DIR}/modules/cvematch.sh"
source "${SCRIPT_DIR}/modules/osint.sh"
source "${SCRIPT_DIR}/modules/cloud.sh"
source "${SCRIPT_DIR}/modules/findings_db.sh"
source "${SCRIPT_DIR}/modules/reporting.sh"
source "${SCRIPT_DIR}/modules/integrations.sh"

# ──────────────────────────────────────────────────────────────────────────────
# Runtime variables
# ──────────────────────────────────────────────────────────────────────────────
TARGET_DOMAIN=""
TARGET_FILE=""
TARGET_TYPE=""        # auto-detected: domain | url | ip | cidr | file
SCOPE_CONF=""
RUN_ENUM=false
RUN_SCAN=false
RUN_CLOUD=false
RUN_REPORT=false
RUN_DIFF=false
RUN_OSINT=true
RUN_CI=false           # --ci         : exit non-zero if HIGH+ findings found
RUN_BASELINE=false     # --baseline   : suppress known findings from report
RUN_PASSIVE=false      # --passive-only: zero-packet recon only
RUN_SCREENSHOTS=false  # --screenshots: capture visual snapshots of web targets
RUN_CVE_MATCH=false    # --cve        : correlate fingerprints with NVD
RUN_CRAWL=false        # --crawl      : run dedicated deep crawler phase
OUTPUT_FILE=""
MODE="medium"
AUTO_MODE=false
PROXY_URL=""           # --proxy URL
SLACK_NOTIFY=false
TEAMS_NOTIFY=false
SIEM_NOTIFY=false
VERBOSE=false
SCHEDULE_EXPR=""
INTERVAL_HOURS=""
UNSCHEDULE=false
LIST_SCHEDULES=false

# ──────────────────────────────────────────────────────────────────────────────
# Help
# ──────────────────────────────────────────────────────────────────────────────
show_help() {
    print_banner
    cat <<'HELPEOF'
Usage: ./exposurescopex.sh [options]

TARGET
  -d, --domain DOMAIN       Single target domain
  -f, --file   FILE         File with list of domains

SCAN PHASES
  -e, --enum                Subdomain enumeration + DNS recon
  -s, --scan                Port scan + SSL/TLS + web test + API + vuln scan
  -c, --cloud               Cloud misconfiguration + bucket enumeration
  -r, --report              Generate MD / HTML / PDF / SARIF report

SCAN OPTIONS
  -m, --mode   LEVEL        Scan speed: light | medium | aggressive (default: medium)
  -o, --output FILE         Custom output file prefix
      --no-osint            Skip OSINT module (Shodan/VT API calls)
      --scope  FILE         Scope file — only scan listed domains/CIDRs
      --diff                Compare results to previous scan, report changes
      --baseline            Suppress known findings; report only new ones
      --proxy  URL          Route tool traffic through proxy (e.g. http://127.0.0.1:8080)
      --ci                  Exit non-zero if HIGH+ findings found (for CI/CD pipelines)

CONTINUOUS MONITORING
      --schedule CRON       Register cron job (e.g. "0 2 * * *") then exit
      --interval HOURS      Schedule every N hours (1/6/12/24/48/168)
      --unschedule          Remove scheduled monitoring for the target
      --list-schedules      Show all active ExposureScopeX cron entries

NOTIFICATIONS
      --slack               Send results to Slack
      --teams               Send results to Microsoft Teams
      --siem                Forward logs to SIEM (Splunk HEC / syslog)

MISC
      --auto                Non-interactive mode (no prompts)
  -v, --verbose             Debug output
  -h, --help                This message

CI/CD EXIT CODES (when --ci is set)
  0 = No HIGH or CRITICAL findings
  1 = HIGH findings present
  2 = CRITICAL findings present

EXAMPLES
  # Full one-time scan with report
  ./exposurescopex.sh -d example.com -e -s -c -r

  # Scan through Burp Suite proxy
  ./exposurescopex.sh -d example.com -s -r --proxy http://127.0.0.1:8080

  # Diff against previous run (change detection)
  ./exposurescopex.sh -d example.com -e -s -r --diff

  # Only new findings (suppress known)
  ./exposurescopex.sh -d example.com -e -s -r --diff --baseline

  # CI/CD pipeline gate
  ./exposurescopex.sh -d example.com -s --auto --ci && echo "clean" || echo "findings!"

  # Schedule nightly at 02:00 with Slack alerts, then exit
  ./exposurescopex.sh -d example.com --schedule "0 2 * * *" --slack

  # Shorthand: schedule every 24 hours
  ./exposurescopex.sh -d example.com --interval 24 --slack

  # Batch file scan (OSINT + cloud run per-domain)
  ./exposurescopex.sh -f targets.txt -s -c -r --auto --slack

HELPEOF
}

# ──────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ──────────────────────────────────────────────────────────────────────────────
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -d|--domain|-t|--target) TARGET_DOMAIN="$2"; shift ;;
        -f|--file)          TARGET_FILE="$2";    shift ;;
        -e|--enum)          RUN_ENUM=true ;;
        -s|--scan)          RUN_SCAN=true ;;
        -x|--exploit)       log_error "Exploitation is not supported by ExposureScopeX"; exit 2 ;;
        -c|--cloud)         RUN_CLOUD=true ;;
        -o|--output)        OUTPUT_FILE="$2";    shift ;;
        -m|--mode)          MODE="$2";           shift ;;
        -r|--report)        RUN_REPORT=true ;;
        -v|--verbose)       VERBOSE=true ;;
        --no-osint)         RUN_OSINT=false ;;
        --diff)             RUN_DIFF=true ;;
        --baseline)         RUN_BASELINE=true; RUN_DIFF=true ;;
        --scope)            SCOPE_CONF="$2";     shift ;;
        --proxy)            PROXY_URL="$2";      shift ;;
        --ci)               RUN_CI=true ;;
        --passive-only)     RUN_PASSIVE=true ;;
        --screenshots)      RUN_SCREENSHOTS=true ;;
        --cve)              RUN_CVE_MATCH=true ;;
        --crawl)            RUN_CRAWL=true ;;
        --agent|--agent-model|--agent-max-steps)
            log_error "AI-directed scanning is not supported; scans use deterministic profiles"
            exit 2
            ;;
        --stealth)          STEALTH_MODE=true ;;
        --stealth-min)      STEALTH_DELAY_MIN="$2"; shift ;;
        --stealth-max)      STEALTH_DELAY_MAX="$2"; shift ;;
        --slack)            SLACK_NOTIFY=true ;;
        --teams)            TEAMS_NOTIFY=true ;;
        --siem)             SIEM_NOTIFY=true ;;
        --auto)             AUTO_MODE=true ;;
        --schedule)         SCHEDULE_EXPR="$2";  shift ;;
        --interval)         INTERVAL_HOURS="$2"; shift ;;
        --unschedule)       UNSCHEDULE=true ;;
        --list-schedules)   LIST_SCHEDULES=true ;;
        -h|--help)          show_help; exit 0 ;;
        *) log_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
    shift
done

# ──────────────────────────────────────────────────────────────────────────────
# Proxy: set environment variables so curl and most tools pick it up
# ──────────────────────────────────────────────────────────────────────────────
if [ -n "$PROXY_URL" ]; then
    export http_proxy="$PROXY_URL"
    export https_proxy="$PROXY_URL"
    export HTTP_PROXY="$PROXY_URL"
    export HTTPS_PROXY="$PROXY_URL"
    log_info "Proxy configured: $PROXY_URL"
fi

# ──────────────────────────────────────────────────────────────────────────────
# Scheduling-only commands (no scan; exit immediately after)
# ──────────────────────────────────────────────────────────────────────────────
if [ "$LIST_SCHEDULES" = true ]; then
    list_schedules
    exit 0
fi

if [ "$UNSCHEDULE" = true ]; then
    [ -z "$TARGET_DOMAIN" ] && { log_error "--unschedule requires -d <domain>"; exit 1; }
    remove_schedule "$TARGET_DOMAIN"
    exit 0
fi

if [ -n "$INTERVAL_HOURS" ]; then
    [ -z "$TARGET_DOMAIN" ] && { log_error "--interval requires -d <domain>"; exit 1; }
    SCHEDULE_EXPR=$(hours_to_cron "$INTERVAL_HOURS")
    log_info "Interval ${INTERVAL_HOURS}h → cron: $SCHEDULE_EXPR"
fi

if [ -n "$SCHEDULE_EXPR" ]; then
    [ -z "$TARGET_DOMAIN" ] && { log_error "--schedule requires -d <domain>"; exit 1; }
    print_banner
    setup_schedule "$TARGET_DOMAIN" "$SCHEDULE_EXPR"
    log_success "Monitoring scheduled for $TARGET_DOMAIN. Verify: crontab -l"
    exit 0
fi

# ──────────────────────────────────────────────────────────────────────────────
# Auto-select scan phases based on detected target type.
# Only called when the user provided NO explicit phase flags.
# ──────────────────────────────────────────────────────────────────────────────
auto_select_phases() {
    local type=$1
    log_info "Auto-selected phases for target type: $type"
    case "$type" in
        domain)
            # Full workflow: enum → DNS → OSINT → port → SSL → web → API → vuln → cloud → report
            RUN_ENUM=true; RUN_SCAN=true; RUN_CLOUD=true; RUN_REPORT=true
            ;;
        url)
            # URL already has a specific entry point — skip subdomain enum, DNS, OSINT, cloud
            RUN_SCAN=true; RUN_REPORT=true; RUN_OSINT=false
            ;;
        ip)
            # Skip enum/DNS/email; run port scan, web (if http open), vuln, cloud, OSINT (IP-based)
            RUN_SCAN=true; RUN_CLOUD=true; RUN_REPORT=true
            ;;
        cidr)
            # Ping sweep → port scan → vuln scan; skip domain-specific phases
            RUN_SCAN=true; RUN_REPORT=true; RUN_OSINT=false
            ;;
        file)
            # Mixed file: enable all phases; per-line type detection skips inapplicable modules
            RUN_ENUM=true; RUN_SCAN=true; RUN_CLOUD=true; RUN_REPORT=true
            ;;
    esac
}

# ──────────────────────────────────────────────────────────────────────────────
# Helper: iterate file targets for per-target operations.
# Accepts any valid target type per line (domain, URL, IP, CIDR).
# Calls $1 (function name) for each valid, in-scope entry.
# ──────────────────────────────────────────────────────────────────────────────
_run_per_domain() {
    local fn=$1
    local accepted_types=${2:-domain,url,ip,cidr}
    if [ -n "$TARGET_DOMAIN" ]; then
        local single_type
        single_type=$(detect_target_type "$TARGET_DOMAIN" 2>/dev/null)
        if [[ ",$accepted_types," == *",$single_type,"* ]]; then
            "$fn" "$TARGET_DOMAIN" "$SESSION_DIR"
        else
            log_info "[$single_type] Skipping $fn (not applicable)"
        fi
    elif [ -n "$TARGET_FILE" ]; then
        while IFS= read -r target; do
            [[ -z "$target" || "$target" =~ ^# ]] && continue
            local ttype
            ttype=$(detect_target_type "$target" 2>/dev/null)
            if [ "$ttype" = "unknown" ]; then
                log_warn "Skipping unrecognized target: $target"
                continue
            fi
            if [ -n "$SCOPE_CONF" ] && ! is_in_scope "$target"; then
                log_warn "Out of scope, skipping: $target"
                continue
            fi
            if [[ ",$accepted_types," != *",$ttype,"* ]]; then
                continue
            fi
            log_info "[$ttype] Running $fn for $target..."
            "$fn" "$target" "$SESSION_DIR"
        done < "$TARGET_FILE"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Apply baseline filter: keep only findings NOT present in previous state
# ──────────────────────────────────────────────────────────────────────────────
_apply_baseline() {
    local session_dir=$1
    local prev_state=$2
    local nuclei_file="${session_dir}/nuclei_results.txt"

    [ ! -f "$nuclei_file" ] && return 0
    [ -z "$prev_state" ] || [ ! -f "$prev_state" ] && {
        log_warn "--baseline has no previous state to compare — showing all findings"
        return 0
    }

    local prev_vulns current_vulns new_only
    prev_vulns=$(jq -r '.vulns[]?' "$prev_state" 2>/dev/null | sort)
    current_vulns=$(sort "$nuclei_file")
    new_only=$(comm -13 <(echo "$prev_vulns") <(echo "$current_vulns") 2>/dev/null | grep -v '^$' || true)

    local orig_count
    orig_count=$(wc -l < "$nuclei_file" 2>/dev/null || echo 0)

    if [ -z "$new_only" ]; then
        log_info "Baseline: all $orig_count findings were present in previous scan — nothing new"
        : > "$nuclei_file"
    else
        echo "$new_only" > "$nuclei_file"
        local new_count
        new_count=$(wc -l < "$nuclei_file" 2>/dev/null || echo 0)
        log_info "Baseline: $new_count new findings (suppressed $((orig_count - new_count)) known)"
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Main scan workflow
# ──────────────────────────────────────────────────────────────────────────────
main() {
    print_banner
    log_info "ExposureScopeX v2.2.0 starting..."

    # ── Validate targets ───────────────────────────────────────────────────
    if [ -z "$TARGET_DOMAIN" ] && [ -z "$TARGET_FILE" ]; then
        log_error "No target specified. Use -d or -f."
        show_help
        exit 1
    fi

    if [ -n "$TARGET_DOMAIN" ]; then
        TARGET_TYPE=$(detect_target_type "$TARGET_DOMAIN")
        if [ "$TARGET_TYPE" = "unknown" ]; then
            log_fatal "Cannot determine type for: $TARGET_DOMAIN — expected domain, URL, IP, or CIDR"
        fi
        log_info "Target: $TARGET_DOMAIN  [type: $TARGET_TYPE]"
    fi

    if [ -n "$TARGET_FILE" ]; then
        validate_file "$TARGET_FILE" || log_fatal "Target file not found: $TARGET_FILE"
        TARGET_TYPE="file"
        log_info "Target file: $TARGET_FILE  [type: file — domain/URL/IP/CIDR lines accepted]"
    fi

    # ── Auto-select phases when none were specified explicitly ─────────────
    if [ "$RUN_ENUM" = false ] && [ "$RUN_SCAN" = false ] && \
       [ "$RUN_CLOUD" = false ] && [ "$RUN_REPORT" = false ]; then
        auto_select_phases "$TARGET_TYPE"
    fi

    # ── Scope loading ──────────────────────────────────────────────────────
    if [ -n "$SCOPE_CONF" ]; then
        load_scope "$SCOPE_CONF" || log_fatal "Scope load failed; refusing to run without enforcement"
        print_scope
        if [ -n "$TARGET_DOMAIN" ]; then
            assert_in_scope "$TARGET_DOMAIN" || log_fatal "Primary target is out of scope"
        fi
    fi

    # ── Passive-only mode: block any active phases ─────────────────────────
    if [ "$RUN_PASSIVE" = true ]; then
        RUN_SCAN=false; RUN_CLOUD=false
        log_info "[passive-only] Active scan phases disabled — running passive recon only"
    fi

    # ── Stealth mode announcement ──────────────────────────────────────────
    if [ "$STEALTH_MODE" = true ]; then
        log_info "[stealth] Randomised inter-tool delays: ${STEALTH_DELAY_MIN}–${STEALTH_DELAY_MAX}s"
    fi

    # ── Dependencies ───────────────────────────────────────────────────────
    check_dependency "curl"
    check_dependency "jq"

    # ── Session directory ──────────────────────────────────────────────────
    if [ -n "$TARGET_DOMAIN" ]; then
        SESSION_DIR="${RESULTS_DIR}/$(sanitize_filename "$TARGET_DOMAIN")_$(date +%Y%m%d_%H%M%S)"
    else
        SESSION_DIR="${RESULTS_DIR}/batch_$(date +%Y%m%d_%H%M%S)"
    fi
    mkdir -p "$SESSION_DIR"
    : > "${SESSION_DIR}/tool_runs.tsv"
    log_info "Session: $SESSION_DIR"

    # ── Load previous state for diff/baseline ─────────────────────────────
    PREV_STATE_FILE=""
    if { [ "$RUN_DIFF" = true ] || [ "$RUN_BASELINE" = true ]; } && [ -n "$TARGET_DOMAIN" ]; then
        PREV_STATE_FILE=$(load_previous_state "$TARGET_DOMAIN" 2>/dev/null || true)
        if [ -n "$PREV_STATE_FILE" ]; then
            log_info "Previous state: $PREV_STATE_FILE"
        else
            log_info "No previous state — this will be the baseline for future runs"
        fi
    fi

    # ── DB init ────────────────────────────────────────────────────────────
    db_init
    db_register_scan "${TARGET_DOMAIN:-${TARGET_FILE:-batch}}" "$SESSION_DIR" "$MODE"

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 0 — Passive Reconnaissance (zero-packet)
    # ──────────────────────────────────────────────────────────────────────
    if [ "$RUN_PASSIVE" = true ] || [ "$RUN_ENUM" = true ]; then
        run_bounded_stage passive_recon 120 _run_per_domain run_passive_recon domain
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 1 — Enumeration
    # ──────────────────────────────────────────────────────────────────────
    if [ "$RUN_ENUM" = true ]; then
        run_bounded_stage enumeration 240 _run_per_domain run_enumeration domain
        if [ -n "$SCOPE_CONF" ] && [ -f "${SESSION_DIR}/subdomains.txt" ]; then
            filter_by_scope "${SESSION_DIR}/subdomains.txt" "${SESSION_DIR}/subdomains_inscope.txt"
            mv "${SESSION_DIR}/subdomains_inscope.txt" "${SESSION_DIR}/subdomains.txt"
        fi
    elif [ "$RUN_SCAN" = true ] && [ -n "$TARGET_DOMAIN" ] && [ "$AUTO_MODE" = false ]; then
        read -rp "Enumeration skipped. Run it first? (y/n) " choice
        [[ "$choice" =~ ^[Yy]$ ]] && run_enumeration "$TARGET_DOMAIN" "$SESSION_DIR"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 2 — DNS Reconnaissance
    # ──────────────────────────────────────────────────────────────────────
    if { [ "$RUN_ENUM" = true ] || [ "$RUN_SCAN" = true ]; }; then
        run_bounded_stage dns_recon 120 _run_per_domain run_dns_recon domain
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 3 — OSINT (runs per-domain for both -d and -f)
    # ──────────────────────────────────────────────────────────────────────
    if [ "$RUN_OSINT" = true ]; then
        run_bounded_stage osint 120 _run_per_domain run_osint domain
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 4 — Port Scanning
    # ──────────────────────────────────────────────────────────────────────
    if [ "$RUN_SCAN" = true ]; then
        run_bounded_stage port_scan 300 run_port_scan "${TARGET_FILE:-$TARGET_DOMAIN}" "$SESSION_DIR"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 5 — SSL/TLS + HTTP Headers + Email Security (per-domain)
    # ──────────────────────────────────────────────────────────────────────
    if [ "$RUN_SCAN" = true ]; then
        _run_ssl_security_stage() {
            _run_per_domain run_ssl_check domain
            _run_per_domain run_email_security_check domain
        }
        run_bounded_stage ssl_tls 180 _run_ssl_security_stage
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 6 — Cloud Security (runs per-domain for both -d and -f)
    # ──────────────────────────────────────────────────────────────────────
    if [ "$RUN_CLOUD" = true ]; then
        run_bounded_stage cloud 180 _run_per_domain run_cloud_scan domain
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 6b — Deep Web Crawler
    # ──────────────────────────────────────────────────────────────────────
    if [ -n "${EXPOSURESCOPEX_WEB_AUTH_JSON:-}" ]; then
        run_bounded_stage authentication 60 establish_web_auth_session "$SESSION_DIR"
        if [ ! -s "${SESSION_DIR}/web-auth-storage-state.json" ]; then
            local auth_failure="configured authentication did not produce a verified browser session; authenticated stages were not run"
            log_error "[stage-failed] authentication: ${auth_failure}"
            printf '%s\t%s\t%s\n' "authentication" "failed" "$auth_failure" >> "${SESSION_DIR}/coverage_exceptions.tsv"
            return 1
        fi
    fi
    if [ "$RUN_SCAN" = true ] || [ "$RUN_CRAWL" = true ]; then
        crawler_timeout=600
        [ "$MODE" = "light" ] && crawler_timeout=180
        [ "$MODE" = "aggressive" ] && crawler_timeout=1200
        run_bounded_stage crawler "$crawler_timeout" run_crawler "${TARGET_FILE:-$TARGET_DOMAIN}" "$SESSION_DIR"
    fi

    if [ "$RUN_SCAN" = true ]; then
        validation_timeout=600
        [ "$MODE" = "light" ] && validation_timeout=180
        [ "$MODE" = "aggressive" ] && validation_timeout=1200
        run_bounded_stage safe_validation "$validation_timeout" run_safe_web_validation "${TARGET_FILE:-$TARGET_DOMAIN}" "$SESSION_DIR"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 7 — Web Application Testing
    # ──────────────────────────────────────────────────────────────────────
    if [ "$RUN_SCAN" = true ]; then
        web_testing_timeout=900
        [ "$MODE" = "light" ] && web_testing_timeout=180
        [ "$MODE" = "aggressive" ] && web_testing_timeout=1800
        run_bounded_stage web_testing "$web_testing_timeout" run_web_test "${TARGET_FILE:-$TARGET_DOMAIN}" "$SESSION_DIR"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 8 — API Security Testing (per-domain)
    # ──────────────────────────────────────────────────────────────────────
    if [ "$RUN_SCAN" = true ]; then
        run_bounded_stage api_security 180 _run_per_domain run_api_security domain
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 8b — Screenshot Capture
    # ──────────────────────────────────────────────────────────────────────
    if [ "$RUN_SCREENSHOTS" = true ] || [ "$RUN_SCAN" = true ]; then
        run_bounded_stage screenshots 120 run_screenshots "${TARGET_FILE:-$TARGET_DOMAIN}" "$SESSION_DIR"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 9 — Vulnerability Scanning (Nuclei — aggregates all prior output)
    # ──────────────────────────────────────────────────────────────────────
    if [ "$RUN_SCAN" = true ]; then
        nuclei_stage_timeout="${NUCLEI_STAGE_TIMEOUT_MEDIUM:-3660}"
        [ "$MODE" = "light" ] && nuclei_stage_timeout="${NUCLEI_STAGE_TIMEOUT_LIGHT:-1860}"
        [ "$MODE" = "aggressive" ] && nuclei_stage_timeout="${NUCLEI_STAGE_TIMEOUT_AGGRESSIVE:-7260}"
        run_bounded_stage nuclei "$nuclei_stage_timeout" run_vuln_scan "${TARGET_FILE:-$TARGET_DOMAIN}" "$SESSION_DIR"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 9b — CVE Correlation
    # ──────────────────────────────────────────────────────────────────────
    if [ "$RUN_CVE_MATCH" = true ] || [ "$RUN_SCAN" = true ]; then
        run_bounded_stage cve_correlation 120 run_cve_match "${TARGET_DOMAIN:-batch}" "$SESSION_DIR"
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 9c — Import findings into DB + print summary
    # ──────────────────────────────────────────────────────────────────────
    db_import_nuclei "$SESSION_DIR"
    db_print_summary

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 11 — State save + change detection + baseline filter
    # ──────────────────────────────────────────────────────────────────────
    _finalize_scan_state() {
        [ -n "$TARGET_DOMAIN" ] || return 0
        if [ "$RUN_DIFF" = true ] && [ -n "$PREV_STATE_FILE" ]; then
            diff_states "$PREV_STATE_FILE" "$SESSION_DIR"
        fi
        if [ "$RUN_BASELINE" = true ]; then
            _apply_baseline "$SESSION_DIR" "$PREV_STATE_FILE"
        fi
        save_state "$TARGET_DOMAIN" "$SESSION_DIR"
        update_latest_symlink "$TARGET_DOMAIN" "$SESSION_DIR"
    }
    if [ "$RUN_DIFF" = true ]; then
        run_bounded_stage historical_diff 120 _finalize_scan_state
    else
        _finalize_scan_state
    fi

    # ──────────────────────────────────────────────────────────────────────
    # PHASE 12 — Reporting + notifications
    # ──────────────────────────────────────────────────────────────────────
    _do_report_and_notify() {
        local label="${TARGET_DOMAIN:-batch}"
        generate_report_and_notify "$SESSION_DIR" "$label"
    }

    if [ "$RUN_REPORT" = true ]; then
        run_bounded_stage reporting 120 _do_report_and_notify
    elif [ "$RUN_SCAN" = true ] && [ "$AUTO_MODE" = false ]; then
        read -rp "Scan finished. Generate report? (y/n) " choice
        [[ "$choice" =~ ^[Yy]$ ]] && _do_report_and_notify
    fi

    log_success "ExposureScopeX session complete: $SESSION_DIR"

    # ──────────────────────────────────────────────────────────────────────
    # CI/CD exit codes — must be last
    # ──────────────────────────────────────────────────────────────────────
    if [ "$RUN_CI" = true ]; then
        local critical_count=0 high_count=0
        if [ -f "${SESSION_DIR}/nuclei_results.txt" ]; then
            critical_count=$(grep -ci "\[critical\]" "${SESSION_DIR}/nuclei_results.txt" 2>/dev/null || true)
            high_count=$(grep -ci "\[high\]"         "${SESSION_DIR}/nuclei_results.txt" 2>/dev/null || true)
        fi
        if [ "$critical_count" -gt 0 ]; then
            log_warn "CI: $critical_count CRITICAL finding(s) — exit 2"
            exit 2
        elif [ "$high_count" -gt 0 ]; then
            log_warn "CI: $high_count HIGH finding(s) — exit 1"
            exit 1
        fi
        log_success "CI: No HIGH or CRITICAL findings — exit 0"
    fi
}

trap 'handle_interrupt' SIGINT SIGTERM

main
