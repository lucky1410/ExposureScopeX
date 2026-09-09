#!/bin/bash

# OSINT Module
# Shodan (via IP), VirusTotal, Censys, HIBP, theHarvester, git leak detection

run_osint() {
    local target=$1
    local output_dir=$2
    local osint_output="${output_dir}/osint_results.txt"

    log_info "Starting OSINT for $target"

    if ! validate_domain "$target"; then
        log_error "Invalid OSINT target: $target"
        return 1
    fi

    touch "$osint_output"

    # -----------------------------------------------------------------------
    # Shodan — resolve domain to IP first (the /shodan/host API requires an IP)
    # -----------------------------------------------------------------------
    if [ -n "$SHODAN_API_KEY" ]; then
        log_info "Querying Shodan API..."
        local shodan_ips
        shodan_ips=$(dig +short A "$target" 2>/dev/null | grep -E '^[0-9]+\.' | head -5)

        if [ -z "$shodan_ips" ]; then
            log_warn "Could not resolve $target to an IP — skipping Shodan host lookup"
        else
            while IFS= read -r ip; do
                log_info "  Shodan host lookup: $ip"
                curl -s "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}" \
                    | jq . > "${output_dir}/shodan_${ip//./_}.json" 2>/dev/null || \
                    log_warn "Shodan API query failed for $ip"
            done <<< "$shodan_ips"
        fi

        # Domain-based search (returns hosts mentioning the domain in their data)
        curl -s "https://api.shodan.io/shodan/host/search?key=${SHODAN_API_KEY}&query=hostname:${target}" \
            | jq . > "${output_dir}/shodan_search.json" 2>/dev/null || true
    else
        log_info "SHODAN_API_KEY not set — skipping Shodan"
    fi

    # -----------------------------------------------------------------------
    # VirusTotal
    # -----------------------------------------------------------------------
    if [ -n "$VIRUSTOTAL_API_KEY" ]; then
        log_info "Querying VirusTotal..."
        curl -s --header "x-apikey: $VIRUSTOTAL_API_KEY" \
            "https://www.virustotal.com/api/v3/domains/$target" \
            | jq . > "${output_dir}/vt_data.json" 2>/dev/null || \
            log_warn "VirusTotal query failed"

        # Passive DNS resolutions from VT
        curl -s --header "x-apikey: $VIRUSTOTAL_API_KEY" \
            "https://www.virustotal.com/api/v3/domains/$target/resolutions?limit=20" \
            | jq -r '.data[]?.attributes?.ip_address // empty' \
            >> "$osint_output" 2>/dev/null || true
    else
        log_info "VIRUSTOTAL_API_KEY not set — skipping VirusTotal"
    fi

    # -----------------------------------------------------------------------
    # Censys
    # -----------------------------------------------------------------------
    if [ -n "$CENSYS_API_ID" ] && [ -n "$CENSYS_API_SECRET" ]; then
        log_info "Querying Censys..."
        curl -s --user "${CENSYS_API_ID}:${CENSYS_API_SECRET}" \
            -H "Content-Type: application/json" \
            -d "{\"q\":\"${target}\"}" \
            "https://search.censys.io/api/v2/hosts/search" \
            | jq . > "${output_dir}/censys_data.json" 2>/dev/null || \
            log_warn "Censys query failed"
    fi

    # -----------------------------------------------------------------------
    # Have I Been Pwned — domain breach check
    # -----------------------------------------------------------------------
    log_info "Checking Have I Been Pwned..."
    local hibp_resp
    hibp_resp=$(curl -s --max-time 10 \
        -H "User-Agent: ExposureScopeX/1.0" \
        "https://haveibeenpwned.com/api/v3/breacheddomain/${target}" 2>/dev/null)

    if [ -n "$hibp_resp" ] && ! echo "$hibp_resp" | grep -q '"statusCode":404'; then
        local breach_count
        breach_count=$(echo "$hibp_resp" | jq 'length' 2>/dev/null || echo "?")
        {
            echo "=== HIBP Breach Data: $target ==="
            echo "Accounts found in $breach_count breach(es)"
            echo "$hibp_resp" | jq . 2>/dev/null || echo "$hibp_resp"
            echo ""
        } >> "$osint_output"
        log_warn "HIBP: $target found in $breach_count breach database(s)"
    else
        echo "HIBP: No breach data found for $target" >> "$osint_output"
        log_info "HIBP: no breaches found for $target"
    fi

    # -----------------------------------------------------------------------
    # theHarvester — emails, subdomains, employee OSINT
    # -----------------------------------------------------------------------
    local harvester_bin
    harvester_bin=$(command -v theHarvester 2>/dev/null || command -v theharvester 2>/dev/null || true)
    if [ -n "$harvester_bin" ]; then
        log_info "Running theHarvester..."
        local harvester_out="${output_dir}/theharvester"
        "$harvester_bin" -d "$target" -b all -f "$harvester_out" >/dev/null 2>&1 || \
            log_warn "theHarvester encountered errors (some sources may have failed)"
        [ -f "${harvester_out}.xml" ] && log_success "theHarvester: ${harvester_out}.xml"
    fi

    # -----------------------------------------------------------------------
    # Git credential leak scanning (trufflehog → gitleaks → git-hound)
    # -----------------------------------------------------------------------
    log_info "Scanning for git credential leaks..."
    local git_leak_out="${output_dir}/git_leaks.txt"
    : > "$git_leak_out"

    if command -v trufflehog &>/dev/null; then
        log_info "  Using trufflehog..."
        trufflehog github --org="$target" --only-verified >> "$git_leak_out" 2>/dev/null || true
    elif command -v gitleaks &>/dev/null; then
        log_info "  Using gitleaks..."
        gitleaks detect --source="$output_dir" \
            --report-path="$git_leak_out" --report-format=json 2>/dev/null || true
    elif command -v git-hound &>/dev/null; then
        log_info "  Using git-hound..."
        echo "$target" | git-hound >> "$git_leak_out" 2>/dev/null || \
            log_warn "git-hound failed"
    else
        log_info "  No git leak scanner found (install trufflehog, gitleaks, or git-hound)"
    fi

    [ -s "$git_leak_out" ] && \
        log_warn "Git leaks found — review: $git_leak_out" || \
        log_success "No git leaks detected"

    log_success "OSINT module complete: $osint_output"
    return 0
}
