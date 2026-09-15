#!/bin/bash

# Reporting Module
# Generates Markdown, HTML, PDF, and SARIF reports

html_escape() {
    local str="$1"
    str="${str//&/&amp;}"
    str="${str//</&lt;}"
    str="${str//>/&gt;}"
    str="${str//\"/&quot;}"
    str="${str//\'/&#39;}"
    echo "$str"
}

# ---------------------------------------------------------------------------
# Vulnerability Summary (fixes the previously missing function)
# ---------------------------------------------------------------------------
generate_vuln_summary() {
    local session_dir=$1

    echo "## Vulnerability Summary"
    echo ""

    local nuclei_file="${session_dir}/nuclei_results.txt"
    local has_data=false

    # Count by severity
    local critical=0 high=0 medium=0 low=0 info=0
    if [ -f "$nuclei_file" ] && [ -s "$nuclei_file" ]; then
        critical=$(grep -ci "\[critical\]" "$nuclei_file" 2>/dev/null || true)
        high=$(grep -ci "\[high\]"     "$nuclei_file" 2>/dev/null || true)
        medium=$(grep -ci "\[medium\]" "$nuclei_file" 2>/dev/null || true)
        low=$(grep -ci "\[low\]"       "$nuclei_file" 2>/dev/null || true)
        info=$(grep -ci "\[info\]"     "$nuclei_file" 2>/dev/null || true)
        has_data=true
    fi

    # Additional tool findings
    local nikto_count=0 ssl_issues=0 header_issues=0 api_issues=0

    for f in "${session_dir}"/nikto_*.txt; do
        [ -f "$f" ] && nikto_count=$(( nikto_count + $(grep -c "OSVDB\|+" "$f" 2>/dev/null || true) ))
    done

    [ -f "${session_dir}/ssl_results.txt" ] && \
        ssl_issues=$(grep -c "\[WEAK\]\|\[CRITICAL\]\|\[HIGH\]" "${session_dir}/ssl_results.txt" 2>/dev/null || true)

    [ -f "${session_dir}/http_headers.txt" ] && \
        header_issues=$(grep -c "\[MISSING\]\|\[MISCONFIGURATION\]" "${session_dir}/http_headers.txt" 2>/dev/null || true)

    [ -f "${session_dir}/api_security.txt" ] && \
        api_issues=$(grep -c "\[CRITICAL\]\|\[HIGH\]\|\[MEDIUM\]" "${session_dir}/api_security.txt" 2>/dev/null || true)

    local total=$(( critical + high + medium + low + info ))

    if [ "$total" -eq 0 ] && [ "$nikto_count" -eq 0 ] && [ "$ssl_issues" -eq 0 ]; then
        echo "_No vulnerability data available — run with \`-s\` to enable scanning_"
        echo ""
        return
    fi

    # Severity table (nuclei findings)
    echo "### Nuclei Findings"
    echo ""
    echo "| Severity | Count |"
    echo "|----------|------:|"
    echo "| 🔴 Critical | $critical |"
    echo "| 🟠 High     | $high |"
    echo "| 🟡 Medium   | $medium |"
    echo "| 🔵 Low      | $low |"
    echo "| ℹ️  Info     | $info |"
    echo "| **Total**   | **$total** |"
    echo ""

    # Risk rating
    local risk="Low"
    [ "$critical" -gt 0 ] && risk="Critical"
    [ "$critical" -eq 0 ] && [ "$high" -gt 0 ] && risk="High"
    [ "$critical" -eq 0 ] && [ "$high" -eq 0 ] && [ "$medium" -gt 0 ] && risk="Medium"

    echo "**Overall Risk Rating: $risk**"
    echo ""

    # Other tool findings
    if [ "$nikto_count" -gt 0 ] || [ "$ssl_issues" -gt 0 ] || [ "$header_issues" -gt 0 ] || [ "$api_issues" -gt 0 ]; then
        echo "### Additional Findings"
        echo ""
        echo "| Source | Count |"
        echo "|--------|------:|"
        [ "$nikto_count"    -gt 0 ] && echo "| Nikto             | $nikto_count |"
        [ "$ssl_issues"     -gt 0 ] && echo "| SSL/TLS Issues    | $ssl_issues |"
        [ "$header_issues"  -gt 0 ] && echo "| Missing Headers   | $header_issues |"
        [ "$api_issues"     -gt 0 ] && echo "| API Security      | $api_issues |"
        echo ""
    fi
}

# ---------------------------------------------------------------------------
# Nmap results formatter
# Correctly tracks "Nmap scan report for <host>" lines to associate
# each port line with its host, rather than guessing from $NF.
# ---------------------------------------------------------------------------
format_nmap_results() {
    local nmap_file=$1
    [ -f "$nmap_file" ] || return

    echo "## Open Ports and Services"
    echo ""
    echo "| Host | Port | State | Service | Version |"
    echo "|------|------|-------|---------|---------|"

    local current_host=""
    while IFS= read -r line; do
        # Track host from: "Nmap scan report for hostname (1.2.3.4)"
        # or:              "Nmap scan report for 1.2.3.4"
        if [[ "$line" =~ ^"Nmap scan report for " ]]; then
            current_host="${line#Nmap scan report for }"
            current_host="${current_host% (*}"   # strip trailing " (ip)" if present
            continue
        fi

        # Port lines look like: "80/tcp   open  http    Apache httpd 2.4.41"
        if [[ "$line" =~ ^[0-9]+/(tcp|udp)[[:space:]]+open ]]; then
            local port state service version
            port=$(awk '{print $1}' <<< "$line")
            state=$(awk '{print $2}' <<< "$line")
            service=$(awk '{print $3}' <<< "$line")
            # Everything from field 4 onwards is the version string
            version=$(awk '{$1=$2=$3=""; sub(/^[[:space:]]+/,"",$0); print}' <<< "$line")
            version=$(html_escape "$version")
            echo "| $current_host | $port | $state | $service | $version |"
        fi
    done < "$nmap_file"
    echo ""
}

# ---------------------------------------------------------------------------
# SARIF output (for CI/CD / GitHub Code Scanning integration)
# ---------------------------------------------------------------------------
generate_sarif_report() {
    local session_dir=$1
    local sarif_output="${session_dir}/report.sarif"
    local nuclei_file="${session_dir}/nuclei_results.txt"

    if ! command -v jq &>/dev/null; then
        log_warn "jq required for SARIF generation — skipping"
        return 1
    fi

    log_info "Generating SARIF report..."

    # Build SARIF results array from nuclei output
    local results_json="[]"
    if [ -f "$nuclei_file" ] && [ -s "$nuclei_file" ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local level="note"
            echo "$line" | grep -qi "\[critical\]\|\[high\]" && level="error"
            echo "$line" | grep -qi "\[medium\]"             && level="warning"

            results_json=$(echo "$results_json" | jq \
                --arg msg "$line" \
                --arg sev "$level" \
                '. + [{"ruleId":"nuclei-finding","level":$sev,"message":{"text":$msg}}]' 2>/dev/null) || true
        done < "$nuclei_file"
    fi

    if jq -n \
        --argjson results "$results_json" \
        '{
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "ExposureScopeX",
                        "version": "1.0.0",
                        "rules": []
                    }
                },
                "results": $results
            }]
        }' > "$sarif_output" 2>/dev/null; then
        log_success "SARIF report: $sarif_output"
        return 0
    fi

    rm -f "$sarif_output"
    log_warn "SARIF generation failed"
    return 1
}

# ---------------------------------------------------------------------------
# HTML report with severity breakdown
# ---------------------------------------------------------------------------
generate_html_report() {
    local session_dir=$1
    local report_md="${session_dir}/report.md"
    local html_output="${session_dir}/report.html"

    if ! command -v pandoc &>/dev/null; then
        log_warn "pandoc required for HTML report — skipping"
        return 0
    fi

    log_info "Generating HTML report..."

    # Count severities for the summary chart data
    local critical=0 high=0 medium=0 low=0 info=0
    if [ -f "${session_dir}/nuclei_results.txt" ]; then
        critical=$(grep -ci "\[critical\]" "${session_dir}/nuclei_results.txt" 2>/dev/null || true)
        high=$(grep -ci "\[high\]"         "${session_dir}/nuclei_results.txt" 2>/dev/null || true)
        medium=$(grep -ci "\[medium\]"     "${session_dir}/nuclei_results.txt" 2>/dev/null || true)
        low=$(grep -ci "\[low\]"           "${session_dir}/nuclei_results.txt" 2>/dev/null || true)
        info=$(grep -ci "\[info\]"         "${session_dir}/nuclei_results.txt" 2>/dev/null || true)
    fi

    # Inject a Chart.js severity bar chart into a header HTML file
    local header_html="${session_dir}/_report_header.html"
    cat > "$header_html" <<HTMLEOF
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 1100px; margin: 40px auto; padding: 0 20px; color: #222; }
  h1 { color: #c0392b; border-bottom: 3px solid #c0392b; padding-bottom: 10px; }
  h2 { color: #2c3e50; border-bottom: 1px solid #bdc3c7; padding-bottom: 6px; margin-top: 40px; }
  table { border-collapse: collapse; width: 100%; margin: 16px 0; }
  th { background: #2c3e50; color: #fff; padding: 10px; text-align: left; }
  td { border: 1px solid #ddd; padding: 8px; }
  tr:nth-child(even) { background: #f9f9f9; }
  code { background: #f4f4f4; padding: 2px 4px; border-radius: 3px; font-size: 0.9em; }
  pre  { background: #1e1e1e; color: #dcdcdc; padding: 16px; border-radius: 6px; overflow-x: auto; }
  .chart-container { width: 500px; height: 300px; margin: 20px 0; }
  .badge-critical { color:#fff; background:#c0392b; padding:2px 8px; border-radius:4px; }
  .badge-high     { color:#fff; background:#e67e22; padding:2px 8px; border-radius:4px; }
  .badge-medium   { color:#fff; background:#f1c40f; padding:2px 8px; border-radius:4px; color:#333; }
  .badge-low      { color:#fff; background:#3498db; padding:2px 8px; border-radius:4px; }
  .badge-info     { color:#fff; background:#95a5a6; padding:2px 8px; border-radius:4px; }
</style>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<div class="chart-container">
  <canvas id="sevChart"></canvas>
</div>
<script>
new Chart(document.getElementById('sevChart'), {
  type: 'bar',
  data: {
    labels: ['Critical','High','Medium','Low','Info'],
    datasets: [{
      label: 'Findings',
      data: [${critical},${high},${medium},${low},${info}],
      backgroundColor: ['#c0392b','#e67e22','#f1c40f','#3498db','#95a5a6']
    }]
  },
  options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } } }
});
</script>
HTMLEOF

    pandoc "$report_md" \
        --standalone \
        --include-before-body="$header_html" \
        --metadata title="ExposureScopeX Security Report" \
        -o "$html_output" 2>/dev/null && \
        log_success "HTML report: $html_output" || \
        log_warn "HTML report generation failed"

    rm -f "$header_html"
}

# ---------------------------------------------------------------------------
# Main report generator
# ---------------------------------------------------------------------------
generate_report() {
    local session_dir=$1
    local report_md="${session_dir}/report.md"
    local report_pdf="${session_dir}/report.pdf"

    log_info "Generating report..."

    {
        echo "# ExposureScopeX Security Report"
        echo ""
        echo "**Generated:** $(date)"
        echo ""
        echo "## Scan Information"
        echo "- **Target:** ${TARGET_DOMAIN:-${TARGET_FILE:-unknown}}"
        echo "- **Session:** $session_dir"
        echo "- **Mode:** ${SCAN_SPEED:-medium}"
        echo "- **Framework Version:** 1.0.0"
        echo ""

        # ── Vulnerability Summary (now properly defined) ──
        generate_vuln_summary "$session_dir"

        # ── Change detection section (if diff was run) ──
        if [ -f "${session_dir}/changes.md" ]; then
            echo ""
            echo "---"
            cat "${session_dir}/changes.md"
            echo ""
        fi

        # ── Subdomains ──
        if [ -f "${session_dir}/subdomains.txt" ] && [ -s "${session_dir}/subdomains.txt" ]; then
            local count
            count=$(wc -l < "${session_dir}/subdomains.txt")
            echo "## Discovered Subdomains ($count)"
            echo ""
            echo '```'
            cat "${session_dir}/subdomains.txt"
            echo '```'
            echo ""
        fi

        # ── Live hosts ──
        if [ -f "${session_dir}/live_hosts.txt" ] && [ -s "${session_dir}/live_hosts.txt" ]; then
            local lcount
            lcount=$(wc -l < "${session_dir}/live_hosts.txt")
            echo "## Live Hosts ($lcount)"
            echo ""
            echo '```'
            cat "${session_dir}/live_hosts.txt"
            echo '```'
            echo ""
        fi

        # ── Port scan ──
        if [ -f "${session_dir}/nmap_scan.txt" ]; then
            format_nmap_results "${session_dir}/nmap_scan.txt"
        fi

        # ── DNS recon ──
        if [ -f "${session_dir}/dns_recon.txt" ]; then
            echo "## DNS Reconnaissance"
            echo ""
            echo '```'
            cat "${session_dir}/dns_recon.txt"
            echo '```'
            echo ""
        fi

        # ── SSL/TLS ──
        if [ -f "${session_dir}/ssl_results.txt" ] && [ -s "${session_dir}/ssl_results.txt" ]; then
            echo "## SSL/TLS Findings"
            echo ""
            echo '```'
            cat "${session_dir}/ssl_results.txt"
            echo '```'
            echo ""
        fi

        # ── HTTP headers ──
        if [ -f "${session_dir}/http_headers.txt" ] && [ -s "${session_dir}/http_headers.txt" ]; then
            echo "## HTTP Security Headers"
            echo ""
            echo '```'
            cat "${session_dir}/http_headers.txt"
            echo '```'
            echo ""
        fi

        # ── Email security ──
        if [ -f "${session_dir}/email_security.txt" ] && [ -s "${session_dir}/email_security.txt" ]; then
            echo "## Email Security (SPF / DKIM / DMARC)"
            echo ""
            echo '```'
            cat "${session_dir}/email_security.txt"
            echo '```'
            echo ""
        fi

        # ── API security ──
        if [ -f "${session_dir}/api_security.txt" ] && [ -s "${session_dir}/api_security.txt" ]; then
            echo "## API Security"
            echo ""
            echo '```'
            cat "${session_dir}/api_security.txt"
            echo '```'
            echo ""
        fi

        # ── Nuclei detailed findings ──
        if [ -f "${session_dir}/nuclei_results.txt" ] && [ -s "${session_dir}/nuclei_results.txt" ]; then
            echo "## Detailed Vulnerability Findings"
            echo ""
            while IFS= read -r line; do
                local escaped
                escaped=$(html_escape "$line")
                case "$line" in
                    *"[critical]"*) echo "**🔴 CRITICAL:** $escaped" ;;
                    *"[high]"*)     echo "**🟠 HIGH:** $escaped" ;;
                    *"[medium]"*)   echo "**🟡 MEDIUM:** $escaped" ;;
                    *"[low]"*)      echo "**🔵 LOW:** $escaped" ;;
                    *"[info]"*)     echo "**ℹ️ INFO:** $escaped" ;;
                    *)               echo "$escaped" ;;
                esac
                echo ""
            done < "${session_dir}/nuclei_results.txt"
        fi

        # ── Cloud findings ──
        if [ -f "${session_dir}/cloud_results.txt" ] && [ -s "${session_dir}/cloud_results.txt" ]; then
            echo "## Cloud Security"
            echo ""
            echo '```'
            cat "${session_dir}/cloud_results.txt"
            echo '```'
            echo ""
        fi

        if [ -f "${session_dir}/cloud_buckets.txt" ] && [ -s "${session_dir}/cloud_buckets.txt" ]; then
            echo "## Cloud Storage Exposure"
            echo ""
            echo '```'
            cat "${session_dir}/cloud_buckets.txt"
            echo '```'
            echo ""
        fi

        # ── OSINT ──
        if [ -f "${session_dir}/osint_results.txt" ] && [ -s "${session_dir}/osint_results.txt" ]; then
            echo "## OSINT Findings"
            echo ""
            echo '```'
            cat "${session_dir}/osint_results.txt"
            echo '```'
            echo ""
        fi

        # ── Recommendations ──
        echo "## Recommendations"
        echo ""
        echo "### Immediate (0–7 days)"
        echo "- Remediate all CRITICAL vulnerabilities"
        echo "- Revoke and rotate any exposed credentials or API keys"
        echo "- Close unnecessary open ports / services"
        echo "- Enforce HSTS and fix wildcard CORS"
        echo ""
        echo "### Short Term (30 days)"
        echo "- Patch all HIGH severity findings"
        echo "- Deploy missing HTTP security headers"
        echo "- Implement/enforce DMARC p=reject"
        echo "- Disable weak TLS protocols (SSLv2/3, TLS 1.0/1.1)"
        echo "- Restrict GraphQL introspection in production"
        echo ""
        echo "### Long Term (90 days)"
        echo "- Implement Web Application Firewall (WAF)"
        echo "- Deploy continuous vulnerability scanning (use \`--schedule\`)"
        echo "- Enable DNSSEC and add CAA records"
        echo "- Implement MTA-STS for email transport security"
        echo "- Establish an incident response runbook"
        echo ""

        echo "---"
        echo "*Report generated by ExposureScopeX Framework v1.0.0*"

    } > "$report_md"

    log_success "Markdown report: $report_md"

    # HTML and PDF are convenience copies. The backend creates the authoritative
    # client DOCX/PDF after ingestion, so converter availability is non-blocking.
    generate_html_report "$session_dir" || \
        log_warn "Optional HTML report generation failed"

    # Markdown and SARIF are the scanner's required report-stage contract.
    if ! generate_sarif_report "$session_dir"; then
        log_error "Required SARIF report generation failed"
        return 1
    fi

    # PDF via pandoc
    if command -v pandoc &>/dev/null; then
        log_info "Converting to PDF..."
        local css_file="${CONFIG_DIR}/report.css"
        local pandoc_opts=()
        [ -f "$css_file" ] && pandoc_opts+=(--css "$css_file")
        if pandoc "$report_md" -o "$report_pdf" "${pandoc_opts[@]}" 2>/dev/null; then
            log_success "PDF report: $report_pdf"
        else
            log_warn "PDF generation failed — markdown report is available"
        fi
    else
        log_warn "pandoc not found — skipping PDF generation"
    fi

    if ! validate_required_report_artifacts "$session_dir"; then
        log_error "Required report artifacts are missing or empty"
        return 1
    fi

    return 0
}

validate_required_report_artifacts() {
    local session_dir=$1
    [ -s "${session_dir}/report.md" ] && [ -s "${session_dir}/report.sarif" ]
}

# Reporting is complete once the local artifacts exist. Optional notification
# channels must not turn a successful report into a failed coverage stage.
generate_report_and_notify() {
    local session_dir=$1
    local label=$2

    generate_report "$session_dir" || return $?
    if [ "${SLACK_NOTIFY:-false}" = true ]; then
        send_slack_notification "ExposureScopeX complete: $label" "${session_dir}/report.pdf" || \
            log_warn "Slack notification delivery failed"
    fi
    if [ "${TEAMS_NOTIFY:-false}" = true ]; then
        send_teams_notification "ExposureScopeX complete: $label" || \
            log_warn "Teams notification delivery failed"
    fi
    if [ "${SIEM_NOTIFY:-false}" = true ]; then
        send_siem_log "Scan complete for $label" "INFO" || \
            log_warn "SIEM notification delivery failed"
    fi
    return 0
}
