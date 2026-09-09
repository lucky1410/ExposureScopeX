#!/bin/bash

# Passive Reconnaissance Module
# Gathers intelligence from PUBLIC DATA SOURCES ONLY.
# Zero packets are sent directly to the target host.
# Safe to run before formal authorization is in place.
#
# Sources used:
#   crt.sh         — certificate transparency logs
#   DNS resolvers  — public resolver queries (not the target's server)
#   Shodan API     — pre-indexed scan data (your packet hits Shodan, not target)
#   VirusTotal API — passive DNS, reputation
#   Censys API     — pre-indexed scan data
#   Wayback Machine — archive.org historical URL database
#   WHOIS          — ICANN registry queries
#   GitHub search  — public code/secrets exposure (via GitHub API if token set)

run_passive_recon() {
    local domain=$1
    local output_dir=$2
    local passive_out="${output_dir}/passive_recon.txt"

    if ! validate_domain "$domain"; then
        log_error "Passive recon requires a domain target (got: $domain)"
        return 1
    fi

    log_info "Starting PASSIVE reconnaissance for $domain"
    log_info "(Zero packets to target — all data from public sources)"

    {
        echo "# Passive Reconnaissance Report"
        echo "# Target:    $domain"
        echo "# Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# Note: No packets were sent directly to $domain"
        echo ""

        # ── 1. Certificate Transparency (crt.sh) ──────────────────────────
        echo "## 1. Certificate Transparency — crt.sh"
        echo ""
        local ct_out="${output_dir}/subdomains_passive.txt"
        curl -sf --max-time 30 \
            "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null | \
            jq -r '.[].name_value' 2>/dev/null | \
            sed 's/\*\.//g' | tr ',' '\n' | \
            grep -E "^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$" | \
            sort -u | tee "$ct_out" || echo "(crt.sh query failed or returned no data)"
        local ct_count
        ct_count=$(wc -l < "$ct_out" 2>/dev/null || echo 0)
        echo ""
        echo "Found $ct_count unique hosts from certificate transparency"
        echo ""

        # ── 2. DNS Record Enumeration (public resolvers) ──────────────────
        echo "## 2. DNS Records (via public resolvers — not the target's server)"
        echo ""
        if command -v dig &>/dev/null; then
            for rtype in A AAAA MX NS TXT SOA CAA; do
                local result
                result=$(dig +short "$rtype" "$domain" 2>/dev/null)
                [ -n "$result" ] && echo "--- $rtype ---" && echo "$result" && echo ""
            done
        else
            echo "(dig not available)"
        fi

        # ── 3. Primary IP & ASN ───────────────────────────────────────────
        echo "## 3. IP & ASN Information"
        echo ""
        local primary_ip=""
        if command -v dig &>/dev/null; then
            primary_ip=$(dig +short A "$domain" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
        fi
        if [ -n "$primary_ip" ]; then
            echo "Primary A record: $primary_ip"
            if command -v whois &>/dev/null; then
                local asn
                asn=$(whois -h whois.cymru.com " -v $primary_ip" 2>/dev/null | tail -1)
                [ -n "$asn" ] && echo "ASN (Team Cymru): $asn"
            fi
            local rdns
            rdns=$(dig +short -x "$primary_ip" 2>/dev/null)
            [ -n "$rdns" ] && echo "Reverse DNS: $rdns"
        else
            echo "(No A record resolved)"
        fi
        echo ""

        # ── 4. WHOIS ──────────────────────────────────────────────────────
        echo "## 4. WHOIS"
        echo ""
        if command -v whois &>/dev/null; then
            whois "$domain" 2>/dev/null | \
                grep -E "Registrar:|Registrant|Creation Date:|Expiry Date:|Registry Expiry|Name Server:|Status:" | \
                head -20 || echo "(WHOIS query failed)"
        else
            echo "(whois not installed)"
        fi
        echo ""

        # ── 5. Shodan — pre-indexed scan data ─────────────────────────────
        echo "## 5. Shodan (pre-indexed, no target contact)"
        echo ""
        if [ -n "${SHODAN_API_KEY:-}" ] && [ -n "$primary_ip" ]; then
            local shodan_data
            shodan_data=$(curl -sf --max-time 15 \
                "https://api.shodan.io/shodan/host/${primary_ip}?key=${SHODAN_API_KEY}" 2>/dev/null)
            if [ -n "$shodan_data" ]; then
                echo "$shodan_data" | jq -r '
                    "IP:           \(.ip_str)",
                    "Org:          \(.org // "unknown")",
                    "ISP:          \(.isp // "unknown")",
                    "Country:      \(.country_name // "unknown")",
                    "OS:           \(.os // "unknown")",
                    "Open Ports:   \(.ports // [] | map(tostring) | join(", "))",
                    "Last Updated: \(.last_update // "unknown")",
                    "Vulns:        \(.vulns // {} | keys | join(", "))"
                ' 2>/dev/null || echo "(Shodan parse error)"

                # Per-service banners
                echo ""
                echo "Service Banners:"
                echo "$shodan_data" | jq -r '
                    .data[]? |
                    "  Port \(.port): \(.product // .transport // "") \(.version // "")"
                ' 2>/dev/null | head -20
            else
                echo "(Shodan returned no data for $primary_ip)"
            fi
        elif [ -z "${SHODAN_API_KEY:-}" ]; then
            echo "(SHODAN_API_KEY not set — add to config/exposurescopex.conf)"
        fi
        echo ""

        # ── 6. VirusTotal Passive DNS / Reputation ────────────────────────
        echo "## 6. VirusTotal Passive DNS & Reputation"
        echo ""
        if [ -n "${VIRUSTOTAL_API_KEY:-}" ]; then
            local vt_data
            vt_data=$(curl -sf --max-time 15 \
                "https://www.virustotal.com/api/v3/domains/${domain}" \
                -H "x-apikey: ${VIRUSTOTAL_API_KEY}" 2>/dev/null)
            if [ -n "$vt_data" ]; then
                echo "$vt_data" | jq -r '
                    .data.attributes |
                    "Reputation:   \(.reputation)",
                    "Malicious:    \(.last_analysis_stats.malicious // 0) / \((.last_analysis_stats | to_entries | map(.value) | add) // 0) engines",
                    "Categories:   \(.categories // {} | to_entries | map("\(.key):\(.value)") | join(", "))"
                ' 2>/dev/null || echo "(VirusTotal parse error)"

                # Passive DNS subdomains from VT
                echo ""
                echo "Subdomains (VT passive DNS):"
                curl -sf --max-time 15 \
                    "https://www.virustotal.com/api/v3/domains/${domain}/subdomains?limit=20" \
                    -H "x-apikey: ${VIRUSTOTAL_API_KEY}" 2>/dev/null | \
                    jq -r '.data[].id' 2>/dev/null | \
                    tee -a "$ct_out" || true
            else
                echo "(VirusTotal returned no data)"
            fi
        else
            echo "(VIRUSTOTAL_API_KEY not set)"
        fi
        echo ""

        # ── 7. Wayback Machine — historical URL discovery ─────────────────
        echo "## 7. Wayback Machine (archive.org)"
        echo ""
        local wb_file="${output_dir}/wayback_urls_passive.txt"
        curl -sf --max-time 30 \
            "http://web.archive.org/cdx/search/cdx?url=*.${domain}&output=text&fl=original&collapse=urlkey&limit=500" \
            2>/dev/null | sort -u > "$wb_file" || true
        local wb_count
        wb_count=$(wc -l < "$wb_file" 2>/dev/null || echo 0)
        echo "Discovered $wb_count historical URLs → $wb_file"
        echo ""
        echo "Notable paths (admin/api/backup):"
        grep -iE "(admin|api|backup|config|upload|secret|key|token|\.env|\.git)" \
            "$wb_file" 2>/dev/null | head -20 || echo "(none found)"
        echo ""

        # ── 8. GitHub Code Search (requires GITHUB_TOKEN) ─────────────────
        echo "## 8. GitHub Public Code Exposure"
        echo ""
        if [ -n "${GITHUB_TOKEN:-}" ]; then
            local gh_results
            gh_results=$(curl -sf --max-time 15 \
                "https://api.github.com/search/code?q=${domain}+in:file&per_page=10" \
                -H "Authorization: token ${GITHUB_TOKEN}" \
                -H "Accept: application/vnd.github.v3+json" 2>/dev/null)
            local gh_count
            gh_count=$(echo "$gh_results" | jq -r '.total_count // 0' 2>/dev/null || echo 0)
            echo "GitHub code results mentioning $domain: $gh_count"
            echo "$gh_results" | jq -r '.items[]? | "  \(.repository.full_name): \(.path)"' \
                2>/dev/null | head -15
        else
            echo "(GITHUB_TOKEN not set — export GITHUB_TOKEN=<personal access token>)"
            echo "Manual: https://github.com/search?q=${domain}&type=code"
        fi
        echo ""

        # ── 9. Search Engine Dork Cheatsheet (manual) ────────────────────
        echo "## 9. Search Engine Dorks (run manually in browser)"
        echo ""
        echo "Google:"
        printf '  site:%s\n' "$domain"
        printf '  site:%s filetype:pdf OR filetype:xlsx OR filetype:docx\n' "$domain"
        printf '  site:%s inurl:admin OR inurl:login OR inurl:portal\n' "$domain"
        printf '  site:%s ext:env OR ext:cfg OR ext:conf OR ext:bak\n' "$domain"
        printf '  "%s" password OR secret OR api_key\n' "$domain"
        echo ""
        echo "Shodan (browser):"
        printf '  hostname:%s\n' "$domain"
        printf '  ssl.cert.subject.cn:"%s"\n' "$domain"
        echo ""

        # ── 10. Merge subdomains ──────────────────────────────────────────
        echo "---"
        echo "Passive recon complete. No packets were sent to $domain."
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

    } > "$passive_out" 2>&1

    # Merge passive subdomains into the main subdomains file
    if [ -f "${output_dir}/subdomains_passive.txt" ] && [ -s "${output_dir}/subdomains_passive.txt" ]; then
        local main_subs="${output_dir}/subdomains.txt"
        if [ -f "$main_subs" ]; then
            sort -u "$main_subs" "${output_dir}/subdomains_passive.txt" -o "$main_subs"
        else
            sort -u "${output_dir}/subdomains_passive.txt" -o "$main_subs"
        fi
        log_info "Passive subdomains merged into subdomains.txt"
    fi

    log_success "Passive recon complete: $passive_out"
    return 0
}
