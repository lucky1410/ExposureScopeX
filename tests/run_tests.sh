#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Minimal environment required by modules ──────────────────────────────────
export LOG_FILE="/dev/null"
export RESULTS_DIR
RESULTS_DIR=$(mktemp -d)
export VERBOSE=false
export AUTO_MODE=false
export INTERRUPT_COUNT=0
export SKIP_THIS_TOOL=false

source "${SCRIPT_DIR}/modules/utils.sh"
source "${SCRIPT_DIR}/modules/scope.sh"

# continuous.sh needs RESULTS_DIR (STATE_DIR="${RESULTS_DIR}/state")
source "${SCRIPT_DIR}/modules/continuous.sh"

# reporting.sh needs log_* from utils.sh; we source it for format_nmap_results
source "${SCRIPT_DIR}/modules/reporting.sh"
source "${SCRIPT_DIR}/modules/crawler.sh"

# ── Test framework ────────────────────────────────────────────────────────────
test_count=0
pass_count=0
fail_count=0

run_test() {
    local test_name=$1
    local test_func=$2
    test_count=$((test_count + 1))
    echo -n "[$test_count] $test_name ... "
    if "$test_func" 2>/dev/null; then
        echo "PASS"
        pass_count=$((pass_count + 1))
    else
        echo "FAIL"
        fail_count=$((fail_count + 1))
    fi
}

# ── Group 1: Input Validation ─────────────────────────────────────────────────

test_domain_validation() {
    validate_domain "example.com"       || return 1
    validate_domain "sub.example.co.uk" || return 1
    if validate_domain "invalid"; then return 1; fi
    if validate_domain "";         then return 1; fi
    return 0
}

test_url_validation() {
    validate_url "https://example.com"           || return 1
    validate_url "http://example.com:8080/path"  || return 1
    if validate_url "not-a-url";  then return 1; fi
    if validate_url "ftp://foo";  then return 1; fi
    return 0
}

test_ip_validation() {
    validate_ip "192.168.1.1"       || return 1
    validate_ip "10.0.0.1"          || return 1
    validate_ip "::1"               || return 1
    validate_ip "255.255.255.255"   || return 1
    if validate_ip "999.999.999.999"; then return 1; fi
    if validate_ip "256.0.0.1";       then return 1; fi
    return 0
}

# ── Group 2: Utility Helpers ──────────────────────────────────────────────────

test_sanitize_filename() {
    local result

    # Special characters become underscores
    result=$(sanitize_filename "example.com/path test:80")
    [[ "$result" == "example.com_path_test_80" ]] || return 1

    # Safe characters are preserved
    result=$(sanitize_filename "my-file_v2.3")
    [[ "$result" == "my-file_v2.3" ]] || return 1

    # All safe chars: letters, digits, dot, dash, underscore
    result=$(sanitize_filename "abc-123_XYZ.txt")
    [[ "$result" == "abc-123_XYZ.txt" ]] || return 1

    return 0
}

test_profile_tool_timeouts() {
    MODE=light
    [ "$(tool_timeout_seconds waybackurls)" -eq 120 ] || return 1
    [ "$(tool_timeout_seconds katana)" -eq 120 ] || return 1
    [ "$(tool_timeout_seconds nuclei)" -eq 1800 ] || return 1
    MODE=medium
    [ "$(tool_timeout_seconds nuclei)" -eq 3600 ] || return 1
    MODE=aggressive
    [ "$(tool_timeout_seconds nuclei)" -eq 7200 ] || return 1
    MODE=medium
    return 0
}

test_katana_fallback_deduplication() (
    local tmp out calls
    tmp=$(mktemp -d)
    out="$tmp/crawl.txt"
    calls="$tmp/calls.txt"
    local -a urls=("https://example.com" "http://example.com")
    MODE=light
    run_tool() {
        local output=""
        while [ "$#" -gt 0 ]; do
            if [ "$1" = "-o" ]; then output=$2; break; fi
            shift
        done
        echo called >> "$calls"
        echo "https://example.com/" > "$output"
        return 0
    }

    _crawl_katana urls "$out" true >/dev/null
    [ "$(wc -l < "$calls")" -eq 1 ] || return 1

    : > "$calls"
    : > "$out"
    _crawl_katana urls "$out" false >/dev/null
    [ "$(wc -l < "$calls")" -eq 2 ] || return 1
    rm -rf "$tmp"
)

test_profile_crawl_depths() (
    unset CRAWL_MAX_DEPTH
    MODE=light; [ "$(_crawl_depth)" -eq 1 ] || return 1
    MODE=medium; [ "$(_crawl_depth)" -eq 3 ] || return 1
    MODE=aggressive; [ "$(_crawl_depth)" -eq 5 ] || return 1
    CRAWL_MAX_DEPTH=7; [ "$(_crawl_depth)" -eq 7 ] || return 1
)

test_bounded_stage_continues_after_timeout() (
    local tmp started elapsed output
    tmp=$(mktemp -d)
    MODE=light
    SESSION_DIR=$tmp
    slow_test_stage() {
        printf 'fixture-1\tfixture-tool\trunning\t\t2026-09-10T00:00:00Z\t\tfixture-tool\ttool.log\n' > "$SESSION_DIR/tool_runs.tsv"
        while :; do :; done
    }
    started=$SECONDS
    output=$(run_bounded_stage test_stage 1 slow_test_stage)
    elapsed=$((SECONDS - started))
    [ "$elapsed" -lt 8 ] || return 1
    echo "$output" | grep -q '\[stage-start\] test_stage' || return 1
    echo "$output" | grep -q '\[stage-timeout\] test_stage' || return 1
    grep -q $'^test_stage\ttimed_out\t' "$tmp/coverage_exceptions.tsv" || return 1
    grep -q $'^fixture-1\tfixture-tool\ttimed_out\t124\t' "$tmp/tool_runs.tsv" || return 1
    rm -rf "$tmp"
)

test_disabled_notifications_do_not_fail_reporting() (
    local tmp
    tmp=$(mktemp -d)
    SLACK_NOTIFY=false
    TEAMS_NOTIFY=false
    SIEM_NOTIFY=false
    generate_report() {
        : > "$1/report.md"
        return 0
    }

    generate_report_and_notify "$tmp" "fixture" || return 1
    [ -f "$tmp/report.md" ] || return 1
    rm -rf "$tmp"
)

test_required_report_artifact_contract() (
    local tmp
    tmp=$(mktemp -d)
    printf '# report\n' > "$tmp/report.md"
    printf '{"version":"2.1.0"}\n' > "$tmp/report.sarif"
    validate_required_report_artifacts "$tmp" || return 1
    : > "$tmp/report.sarif"
    if validate_required_report_artifacts "$tmp"; then return 1; fi
    rm -rf "$tmp"
)

# ── Group 3: Scope Enforcement ────────────────────────────────────────────────

_make_scope_file() {
    local tmp
    tmp=$(mktemp)
    cat > "$tmp" <<'EOF'
# Test scope file
example.com
*.internal.example.com
192.168.1.0/24
10.0.0.5
EOF
    echo "$tmp"
}

_load_test_scope() {
    TEST_SCOPE_FILE=$(_make_scope_file)
    SCOPE_FILE=""
    load_scope "$TEST_SCOPE_FILE" >/dev/null 2>&1
}

test_scope_exact_domain() {
    local sf
    _load_test_scope
    sf=$TEST_SCOPE_FILE
    local rc=0
    is_in_scope "example.com"       || rc=1
    if is_in_scope "other.com"; then rc=1; fi
    if is_in_scope "notexample.com"; then rc=1; fi
    rm -f "$sf"
    return $rc
}

test_scope_wildcard_domain() {
    local sf
    _load_test_scope
    sf=$TEST_SCOPE_FILE
    local rc=0
    # Wildcard *.internal.example.com covers subdomains AND the base
    is_in_scope "sub.internal.example.com"  || rc=1
    is_in_scope "internal.example.com"      || rc=1
    is_in_scope "a.b.internal.example.com"  || rc=1
    # Must NOT match unrelated domains
    if is_in_scope "evil.example.com";  then rc=1; fi
    if is_in_scope "internal.evil.com"; then rc=1; fi
    rm -f "$sf"
    return $rc
}

test_scope_exact_ip() {
    local sf
    _load_test_scope
    sf=$TEST_SCOPE_FILE
    local rc=0
    is_in_scope "10.0.0.5"       || rc=1
    if is_in_scope "10.0.0.6"; then rc=1; fi
    if is_in_scope "10.0.0.4"; then rc=1; fi
    rm -f "$sf"
    return $rc
}

test_scope_cidr_range() {
    local sf
    _load_test_scope
    sf=$TEST_SCOPE_FILE
    local rc=0
    is_in_scope "192.168.1.1"    || rc=1
    is_in_scope "192.168.1.100"  || rc=1
    is_in_scope "192.168.1.254"  || rc=1
    is_in_scope "192.168.1.0"    || rc=1
    if is_in_scope "192.168.2.1";   then rc=1; fi
    if is_in_scope "192.168.0.255"; then rc=1; fi
    if is_in_scope "10.0.0.1";      then rc=1; fi
    rm -f "$sf"
    return $rc
}

test_scope_cidr_bitwise_math() {
    # Test _ip_in_cidr directly without a scope file
    _ip_in_cidr "10.0.0.0"       "10.0.0.0/8"     || return 1
    _ip_in_cidr "10.255.255.255" "10.0.0.0/8"     || return 1
    _ip_in_cidr "10.128.5.99"    "10.0.0.0/8"     || return 1
    if _ip_in_cidr "11.0.0.1"    "10.0.0.0/8";    then return 1; fi

    _ip_in_cidr "172.16.0.1"     "172.16.0.0/12"  || return 1
    _ip_in_cidr "172.31.255.255" "172.16.0.0/12"  || return 1
    if _ip_in_cidr "172.32.0.0"  "172.16.0.0/12"; then return 1; fi

    _ip_in_cidr "192.168.1.1"    "192.168.1.0/24" || return 1
    if _ip_in_cidr "192.168.2.1" "192.168.1.0/24"; then return 1; fi

    # /32 — exact match only
    _ip_in_cidr "1.2.3.4"        "1.2.3.4/32"     || return 1
    if _ip_in_cidr "1.2.3.5"     "1.2.3.4/32";    then return 1; fi

    return 0
}

test_scope_no_file_passthrough() {
    # With no scope file loaded, every target is in scope
    SCOPE_FILE=""
    is_in_scope "anything.example.com" || return 1
    is_in_scope "1.2.3.4"             || return 1
    is_in_scope "192.168.99.99"       || return 1
    return 0
}

# ── Group 4: Continuous Monitoring Helpers ────────────────────────────────────

test_hours_to_cron() {
    [[ "$(hours_to_cron 1)"   == "0 * * * *"    ]] || return 1
    [[ "$(hours_to_cron 6)"   == "0 */6 * * *"  ]] || return 1
    [[ "$(hours_to_cron 12)"  == "0 */12 * * *" ]] || return 1
    [[ "$(hours_to_cron 24)"  == "0 2 * * *"    ]] || return 1
    [[ "$(hours_to_cron 48)"  == "0 2 */2 * *"  ]] || return 1
    [[ "$(hours_to_cron 168)" == "0 2 * * 0"    ]] || return 1
    return 0
}

test_get_state_file() {
    # get_state_file should return a .json path under STATE_DIR
    local sf
    sf=$(get_state_file "example.com")
    [[ "$sf" == "${STATE_DIR}"/*.json ]] || [[ "$sf" == *"/state/"*".json" ]] || return 1
    # Path must be non-empty
    [ -n "$sf" ] || return 1
    return 0
}

# ── Group 5: Nmap Output Parser ───────────────────────────────────────────────

_make_nmap_fixture() {
    cat <<'EOF'
# Nmap 7.94 scan report
Nmap scan report for example.com (93.184.216.34)
Host is up (0.010s latency).

PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
443/tcp open  https    OpenSSL 1.1.1f

Nmap scan report for sub.example.com
Host is up (0.011s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
8080/tcp open  http    nginx 1.18.0
EOF
}

test_nmap_parser_host_tracking() {
    local fixture
    fixture=$(mktemp --suffix=_nmap.txt 2>/dev/null || mktemp)
    _make_nmap_fixture > "$fixture"

    local output
    output=$(format_nmap_results "$fixture" 2>/dev/null)
    rm -f "$fixture"

    # Both hosts must appear in the output table
    echo "$output" | grep -q "example.com"     || return 1
    echo "$output" | grep -q "sub.example.com" || return 1
    return 0
}

test_nmap_parser_port_lines() {
    local fixture
    fixture=$(mktemp --suffix=_nmap.txt 2>/dev/null || mktemp)
    _make_nmap_fixture > "$fixture"

    local output
    output=$(format_nmap_results "$fixture" 2>/dev/null)
    rm -f "$fixture"

    # All four open ports must appear
    echo "$output" | grep -q "80/tcp"   || return 1
    echo "$output" | grep -q "443/tcp"  || return 1
    echo "$output" | grep -q "22/tcp"   || return 1
    echo "$output" | grep -q "8080/tcp" || return 1
    return 0
}

test_nmap_parser_markdown_table() {
    local fixture
    fixture=$(mktemp --suffix=_nmap.txt 2>/dev/null || mktemp)
    _make_nmap_fixture > "$fixture"

    local output
    output=$(format_nmap_results "$fixture" 2>/dev/null)
    rm -f "$fixture"

    # Must produce a markdown table header
    echo "$output" | grep -q "| Host |" || return 1
    echo "$output" | grep -q "|---" || return 1
    return 0
}

test_nmap_parser_empty_file() {
    # format_nmap_results should not error on a missing file
    format_nmap_results "/nonexistent/nmap.txt" 2>/dev/null
    return 0
}

# ── Run all tests ─────────────────────────────────────────────────────────────

echo "ExposureScopeX Test Suite"
echo "========================="
echo ""

echo "--- Input Validation ---"
run_test "Domain validation"            test_domain_validation
run_test "URL validation"               test_url_validation
run_test "IP validation"                test_ip_validation
echo ""

echo "--- Utility Helpers ---"
run_test "sanitize_filename"            test_sanitize_filename
run_test "profile-aware tool timeouts"  test_profile_tool_timeouts
run_test "Katana fallback deduplication" test_katana_fallback_deduplication
run_test "profile-aware crawl depth"    test_profile_crawl_depths
run_test "bounded stage timeout recovery" test_bounded_stage_continues_after_timeout
run_test "disabled notifications preserve report success" test_disabled_notifications_do_not_fail_reporting
run_test "required report artifact contract" test_required_report_artifact_contract
echo ""

echo "--- Scope Enforcement ---"
run_test "Exact domain match"           test_scope_exact_domain
run_test "Wildcard domain match"        test_scope_wildcard_domain
run_test "Exact IP match"               test_scope_exact_ip
run_test "CIDR range match"             test_scope_cidr_range
run_test "CIDR bitwise math"            test_scope_cidr_bitwise_math
run_test "No scope file (pass-all)"     test_scope_no_file_passthrough
echo ""

echo "--- Continuous Monitoring ---"
run_test "hours_to_cron mappings"       test_hours_to_cron
run_test "get_state_file path"          test_get_state_file
echo ""

echo "--- Nmap Output Parser ---"
run_test "Host tracking in table"       test_nmap_parser_host_tracking
run_test "Port lines extracted"         test_nmap_parser_port_lines
run_test "Markdown table structure"     test_nmap_parser_markdown_table
run_test "Missing file (no crash)"      test_nmap_parser_empty_file
echo ""

echo "========================="
printf "Tests run: %d | Passed: %d | Failed: %d\n" \
    "$test_count" "$pass_count" "$fail_count"
echo ""

# Cleanup temp dir
rm -rf "$RESULTS_DIR"

[ "$fail_count" -eq 0 ] || exit 2
