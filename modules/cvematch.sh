#!/bin/bash

# CVE Matching Module
# Extracts technology + version strings from previous scan outputs, then
# queries the NVD (National Vulnerability Database) public REST API for
# known CVEs.  No API key required; free tier = 5 req / 30 seconds.

NVD_API_URL="https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_DELAY=7   # seconds between calls — stays within free-tier limit

run_cve_match() {
    local target=$1
    local output_dir=$2
    local cve_output="${output_dir}/cve_matches.txt"

    if ! command -v curl &>/dev/null || ! command -v jq &>/dev/null; then
        log_warn "CVE match requires curl and jq — skipping"
        return 1
    fi

    log_info "Starting CVE correlation for $target..."
    : > "$cve_output"

    # Collect technology + version pairs from prior scan results
    local -a signatures=()
    _extract_tech_signatures "$output_dir" signatures

    if [ ${#signatures[@]} -eq 0 ]; then
        log_warn "No technology signatures found — run port scan and web test first"
        echo "# CVE Match: no signatures to query" > "$cve_output"
        return 0
    fi

    # Deduplicate signatures
    local -a unique_sigs=()
    local prev_sig=""
    while IFS= read -r sig; do
        [ "$sig" = "$prev_sig" ] && continue
        unique_sigs+=("$sig")
        prev_sig="$sig"
    done < <(printf '%s\n' "${signatures[@]}" | sort -u)

    log_info "Querying NVD for ${#unique_sigs[@]} technology signatures..."

    {
        echo "# CVE Correlation Report"
        echo "# Target:    $target"
        echo "# Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# Source:    NVD REST API v2 (nvd.nist.gov)"
        echo ""
    } >> "$cve_output"

    local queried=0 total_cves=0

    for sig in "${unique_sigs[@]}"; do
        # Respect NVD free-tier rate limit
        [ "$queried" -gt 0 ] && sleep "$NVD_RATE_DELAY"

        log_debug "NVD query: $sig"

        # Build keyword: URL-encode spaces
        local keyword
        keyword=$(echo "$sig" | sed 's/ /+/g')

        local response
        response=$(curl -sf --max-time 20 \
            "${NVD_API_URL}?keywordSearch=${keyword}&resultsPerPage=5" \
            2>/dev/null) || { log_warn "NVD API call failed for: $sig"; queried=$((queried+1)); continue; }

        local result_count
        result_count=$(echo "$response" | jq -r '.totalResults // 0' 2>/dev/null || echo 0)

        if [ "$result_count" -gt 0 ]; then
            {
                echo "## $sig  ($result_count NVD result(s))"
                echo ""
                echo "$response" | jq -r '
                    .vulnerabilities[]? |
                    .cve as $c |
                    "CVE-ID:      \($c.id)",
                    "Published:   \($c.published // "unknown")",
                    "Severity:    \($c.metrics.cvssMetricV31[0]?.cvssData.baseSeverity // $c.metrics.cvssMetricV30[0]?.cvssData.baseSeverity // "UNKNOWN")",
                    "CVSS Score:  \($c.metrics.cvssMetricV31[0]?.cvssData.baseScore // $c.metrics.cvssMetricV30[0]?.cvssData.baseScore // "N/A")",
                    "Description: \($c.descriptions[] | select(.lang=="en") | .value | .[0:250])",
                    "---"
                ' 2>/dev/null
                echo ""
            } >> "$cve_output"

            total_cves=$((total_cves + result_count))
            log_warn "[$sig] $result_count CVE(s) found"
        else
            log_debug "[$sig] No CVEs returned by NVD"
        fi

        queried=$((queried + 1))
    done

    log_success "CVE correlation complete: $total_cves matches across ${#unique_sigs[@]} signatures → $cve_output"
    return 0
}

# ── Signature extraction ───────────────────────────────────────────────────────
# Parses nmap text output and WhatWeb logs for "product version" strings.
# Populates caller's array via nameref.

_extract_tech_signatures() {
    local output_dir=$1
    local -n _out_sigs=$2   # nameref: caller's array

    # ── From nmap text output ──────────────────────────────────────────────
    # Lines look like: "80/tcp  open  http  Apache httpd 2.4.41 ((Ubuntu))"
    if [ -f "${output_dir}/nmap_scan.txt" ]; then
        while IFS= read -r line; do
            [[ "$line" =~ ^[0-9]+/(tcp|udp)[[:space:]]+open ]] || continue
            # Fields 4+ are the version string
            local version_str
            version_str=$(awk '{$1=$2=$3=""; sub(/^[[:space:]]+/,"",$0); print}' <<< "$line")
            # Skip empty or generic placeholders
            [[ -z "$version_str" || "$version_str" == "?" ]] && continue
            # Strip parenthetical OS notes like "((Ubuntu))"
            version_str=$(echo "$version_str" | sed 's/([^)]*)//g; s/  */ /g; s/^ //; s/ $//')
            [ -n "$version_str" ] && _out_sigs+=("$version_str")
        done < "${output_dir}/nmap_scan.txt"
    fi

    # ── From WhatWeb output files ──────────────────────────────────────────
    # WhatWeb uses the pattern:  ProductName[version]
    for f in "${output_dir}"/whatweb_*.txt; do
        [ -f "$f" ] || continue
        grep -oE '[A-Za-z][A-Za-z0-9._-]+\[([0-9]+\.)+[0-9a-zA-Z._-]+\]' "$f" 2>/dev/null | \
        sed 's/\[/ /; s/\]//' | while IFS= read -r sig; do
            _out_sigs+=("$sig")
        done
    done

    # ── From nuclei findings (product/version in template ID) ─────────────
    # Nuclei often names templates like "apache-2.4.41-rce" — extract product+version
    if [ -f "${output_dir}/nuclei_results.txt" ]; then
        grep -oE '[a-z][a-z0-9-]+\-[0-9]+\.[0-9]' "${output_dir}/nuclei_results.txt" 2>/dev/null | \
        sed 's/-/ /' | sort -u | while IFS= read -r sig; do
            _out_sigs+=("$sig")
        done
    fi
}
