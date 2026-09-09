#!/bin/bash

# Autonomous Agent Module
# Uses the Claude API (claude-opus-4-6) to plan and execute security assessment
# steps adaptively. The agent observes findings from each tool call, reasons
# about what to investigate next, and adapts its strategy until it has built
# a comprehensive picture of the target's attack surface.
#
# Requires: ANTHROPIC_API_KEY in config/exposurescopex.conf
# Requires: curl, jq

AGENT_MODEL="${AGENT_MODEL:-claude-opus-4-6}"
AGENT_MAX_ITERATIONS="${AGENT_MAX_ITERATIONS:-25}"
AGENT_API_URL="https://api.anthropic.com/v1/messages"

# ── Entry point ────────────────────────────────────────────────────────────────

run_agent() {
    local target=$1
    local output_dir=$2

    # ── Preflight checks ───────────────────────────────────────────────────
    if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
        log_error "Agent requires ANTHROPIC_API_KEY — add it to config/exposurescopex.conf"
        return 1
    fi
    if ! command -v curl &>/dev/null || ! command -v jq &>/dev/null; then
        log_error "Agent requires curl and jq"
        return 1
    fi

    local target_type
    target_type=$(detect_target_type "$target")

    local agent_log="${output_dir}/agent_session.json"
    local agent_summary="${output_dir}/agent_summary.md"
    local agent_tool_log="${output_dir}/agent_tool_outputs.txt"
    : > "$agent_tool_log"

    log_info "Autonomous Agent starting"
    log_info "  Target   : $target ($target_type)"
    log_info "  Model    : $AGENT_MODEL"
    log_info "  Max steps: $AGENT_MAX_ITERATIONS"
    [ "${STEALTH_MODE:-false}" = true ] && log_info "  Stealth  : ON (${STEALTH_DELAY_MIN}–${STEALTH_DELAY_MAX}s delays)"
    [ "${RUN_PASSIVE:-false}" = true ]  && log_info "  Mode     : PASSIVE-ONLY (active tools blocked)"

    # ── System prompt ──────────────────────────────────────────────────────
    local passive_constraint=""
    if [ "${RUN_PASSIVE:-false}" = true ]; then
        passive_constraint="
CONSTRAINT — PASSIVE-ONLY MODE: You may only call passive_recon, dns_recon, and
osint_lookup. All active scanning tools are blocked. Do not call port_scan,
web_test, web_crawl, api_security, vuln_scan, cloud_scan, or screenshot."
    fi

    local system_prompt
    system_prompt="You are an expert offensive security researcher conducting an authorized penetration test/attack surface assessment. Your objective is to build a comprehensive picture of the target's external attack surface.
$passive_constraint

## Methodology

Phase 1 — Passive Intelligence (always first, zero target contact)
  - Call passive_recon to gather crt.sh, Shodan index, Wayback, GitHub intel
  - Call dns_recon to enumerate all DNS record types and attempt zone transfer
  - Call osint_lookup for Shodan host, VirusTotal, HIBP, git leak detection

Phase 2 — Active Enumeration
  - Call enumerate_subdomains to discover all subdomains with subfinder/amass
  - Run port_scan on the primary domain and each discovered subdomain
  - Run ssl_check on any HTTPS-capable host

Phase 3 — Web Surface
  - Call web_crawl on all live HTTP/S services to discover URLs, APIs, JS files
  - Call api_security to probe for exposed OpenAPI, GraphQL, secrets
  - Call screenshot to visually catalogue all web services

Phase 4 — Vulnerability Assessment
  - Call web_test on web-facing targets for SQLi, XSS, directory traversal
  - Call vuln_scan to run nuclei templates across all discovered assets
  - Call cve_match to correlate technology fingerprints with NVD CVE data
  - Call cloud_scan to enumerate S3/GCS/Azure buckets and K8s exposure

## Adaptive Decision Rules
- Open port 9200/9300 → likely Elasticsearch, run web_test on that port
- Open port 27017 → MongoDB, add to findings as critical exposure
- Open port 6379 → Redis, add to findings as critical exposure
- Open port 2375 → Docker API, add to findings as critical exposure
- Open port 8080/8443 → alternate web service, run web_crawl + web_test
- Subdomain found → port_scan it individually if not done yet
- WhatWeb reveals CMS+version → run cve_match immediately
- Admin/login page in crawl → note as high-interest finding
- Cloud resource patterns in DNS → run cloud_scan
- 403 on bucket → note as exists-but-restricted

## Efficiency Rules
- Do NOT repeat the same tool+target combination twice
- When you have scanned a target, move on rather than rescanning
- Prioritise breadth over depth in early phases, depth in later phases
- Stop when: all subdomains port-scanned, web-facing hosts tested, CVEs correlated

## Output Format
After EACH tool call, write a brief observation (2–3 sentences): what you found
and why you are choosing the next action. When finished, write a comprehensive
## Final Summary section with all significant findings grouped by severity.

Target: $target
Target type: $target_type"

    # ── Initialise conversation ────────────────────────────────────────────
    local messages
    messages=$(jq -n \
        --arg content "Begin security assessment. Target: $target (type: $target_type). Start with passive_recon, then proceed methodically through the phases." \
        '[{"role":"user","content":$content}]')

    # ── Agent summary header ───────────────────────────────────────────────
    {
        echo "# Autonomous Agent — Security Assessment"
        echo ""
        echo "| | |"
        echo "|---|---|"
        echo "| **Target** | $target |"
        echo "| **Type** | $target_type |"
        echo "| **Model** | $AGENT_MODEL |"
        echo "| **Started** | $(date -u +%Y-%m-%dT%H:%M:%SZ) |"
        echo "| **Max Steps** | $AGENT_MAX_ITERATIONS |"
        echo ""
        echo "---"
        echo ""
    } > "$agent_summary"

    # ── Agentic loop ───────────────────────────────────────────────────────
    local iteration=0 stop_reason="" consecutive_no_tools=0

    while [ "$iteration" -lt "$AGENT_MAX_ITERATIONS" ]; do
        iteration=$((iteration + 1))
        log_info "[Agent] Step $iteration/$AGENT_MAX_ITERATIONS"

        # Build API request — system prompt and tools are marked for caching so
        # the API only processes them fully on the first call (~60% token savings).
        local request
        request=$(jq -n \
            --arg model "$AGENT_MODEL" \
            --arg system "$system_prompt" \
            --argjson messages "$messages" \
            --argjson tools "$(_agent_tools_schema)" \
            '{
                model: $model,
                max_tokens: 2048,
                system: [{"type":"text","text":$system,"cache_control":{"type":"ephemeral"}}],
                tools: $tools,
                messages: $messages
            }')

        # Call Claude API — show spinner while waiting
        local response
        printf '[*] [Agent] Thinking...' >&2
        response=$(curl -sf --max-time 90 \
            "$AGENT_API_URL" \
            -H "x-api-key: $ANTHROPIC_API_KEY" \
            -H "anthropic-version: 2023-06-01" \
            -H "anthropic-beta: prompt-caching-2024-07-31" \
            -H "content-type: application/json" \
            -d "$request" 2>/dev/null)
        printf '\r\033[K' >&2   # erase the "Thinking..." line

        if [ -z "$response" ]; then
            log_error "[Agent] API call failed at step $iteration — check ANTHROPIC_API_KEY and network"
            break
        fi

        # Validate response is parseable JSON
        if ! echo "$response" | jq empty 2>/dev/null; then
            log_error "[Agent] API returned invalid JSON at step $iteration — aborting"
            break
        fi

        # Check for API error
        local api_error
        api_error=$(echo "$response" | jq -r '.error.message // empty' 2>/dev/null)
        if [ -n "$api_error" ]; then
            log_error "[Agent] API error: $api_error"
            break
        fi

        stop_reason=$(echo "$response" | jq -r '.stop_reason // "unknown"' 2>/dev/null)

        # Add assistant turn to conversation
        local content_block
        content_block=$(echo "$response" | jq '.content' 2>/dev/null)
        if [ -z "$content_block" ] || [ "$content_block" = "null" ]; then
            log_error "[Agent] Empty content in API response at step $iteration — aborting"
            break
        fi
        local new_messages
        new_messages=$(echo "$messages" | jq \
            --argjson c "$content_block" \
            '. + [{"role":"assistant","content":$c}]' 2>/dev/null)
        if [ -z "$new_messages" ]; then
            log_error "[Agent] Failed to update messages at step $iteration — aborting"
            break
        fi
        messages="$new_messages"

        # ── Extract and display reasoning text ─────────────────────────────
        local reasoning
        reasoning=$(echo "$response" | jq -r '.content[] | select(.type=="text") | .text' 2>/dev/null)
        if [ -n "$reasoning" ]; then
            # Print Claude's reasoning to terminal (up to 8 lines)
            echo "" >&2
            echo "$reasoning" | head -8 | while IFS= read -r rline; do
                log_info "[Agent] $rline"
            done
            local rlines
            rlines=$(echo "$reasoning" | wc -l)
            [ "$rlines" -gt 8 ] && log_info "[Agent] ... ($((rlines - 8)) more reasoning lines)"
            {
                echo "## Step $iteration"
                echo ""
                echo "$reasoning"
                echo ""
            } >> "$agent_summary"
        fi

        # ── Stop if end_turn ───────────────────────────────────────────────
        if [ "$stop_reason" = "end_turn" ]; then
            log_success "[Agent] Assessment complete (model signalled end_turn)"
            break
        fi

        # ── Execute tool calls ─────────────────────────────────────────────
        local tool_results_arr='[]'
        local tools_called=0

        while IFS= read -r tool_use_json; do
            # Skip any line that isn't valid JSON (e.g. from interrupted curl)
            echo "$tool_use_json" | jq empty 2>/dev/null || continue

            local t_id t_name t_target t_mode
            t_id=$(echo "$tool_use_json"     | jq -r '.id // ""')
            t_name=$(echo "$tool_use_json"   | jq -r '.name // ""')
            t_target=$(echo "$tool_use_json" | jq -r '.input.target // ""')
            t_mode=$(echo "$tool_use_json"   | jq -r '.input.mode // ""')
            # Skip if we couldn't get a valid tool id or name
            [ -z "$t_id" ] || [ -z "$t_name" ] && continue
            [ -z "$t_target" ] && t_target="$target"

            echo "" >&2
            log_info "[Agent] ── $t_name ──────────────── target: $t_target"
            echo "### Step $iteration — $t_name → \`$t_target\`" >> "$agent_summary"

            # Execute tool — stream output live to terminal AND capture to file
            local _tool_tmp
            _tool_tmp=$(mktemp)
            register_cleanup "$_tool_tmp"
            {
                echo "=== Step $iteration | $t_name | $t_target ==="
            } >> "$agent_tool_log"
            _agent_execute_tool "$t_name" "$t_target" "$output_dir" "$t_mode" 2>&1 \
                | tee -a "$agent_tool_log" \
                | tee "$_tool_tmp"
            local raw_output
            raw_output=$(cat "$_tool_tmp")
            rm -f "$_tool_tmp"
            echo "" >> "$agent_tool_log"

            # Filter log-prefix noise, strip ANSI colours, then truncate to 100 lines.
            # Full raw output is already saved to agent_tool_log above.
            local filtered total_lines
            filtered=$(echo "$raw_output" | _filter_for_api)
            total_lines=$(echo "$filtered" | wc -l)
            local truncated
            truncated=$(echo "$filtered" | head -100)
            if [ "$total_lines" -gt 100 ]; then
                truncated+=$'\n'"[... $((total_lines - 100)) lines omitted — full output in agent_tool_outputs.txt]"
            fi

            echo "\`\`\`" >> "$agent_summary"
            echo "$truncated" | head -30 >> "$agent_summary"
            echo "\`\`\`" >> "$agent_summary"
            echo "" >> "$agent_summary"

            # Add to tool_results array
            tool_results_arr=$(echo "$tool_results_arr" | jq \
                --arg id "$t_id" \
                --arg content "$truncated" \
                '. + [{"type":"tool_result","tool_use_id":$id,"content":$content}]')

            tools_called=$((tools_called + 1))

        done < <(echo "$response" | jq -c '.content[] | select(.type=="tool_use")' 2>/dev/null)

        # ── No tools called — agent is done reasoning ──────────────────────
        if [ "$tools_called" -eq 0 ]; then
            consecutive_no_tools=$((consecutive_no_tools + 1))
            if [ "$consecutive_no_tools" -ge 2 ]; then
                log_info "[Agent] No tool calls for 2 consecutive steps — stopping"
                break
            fi
        else
            consecutive_no_tools=0
        fi

        # ── Feed tool results back ─────────────────────────────────────────
        if [ "$tools_called" -gt 0 ]; then
            local updated_messages
            updated_messages=$(echo "$messages" | jq \
                --argjson results "$tool_results_arr" \
                '. + [{"role":"user","content":$results}]' 2>/dev/null)
            [ -n "$updated_messages" ] && messages="$updated_messages"
        fi

    done

    # ── Finalise ───────────────────────────────────────────────────────────
    {
        echo ""
        echo "---"
        echo "| | |"
        echo "|---|---|"
        echo "| **Completed** | $(date -u +%Y-%m-%dT%H:%M:%SZ) |"
        echo "| **Steps taken** | $iteration |"
    } >> "$agent_summary"

    # Save full conversation for replay / audit
    echo "$messages" | jq '.' > "$agent_log" 2>/dev/null

    # Import any nuclei findings produced during agent run
    db_import_nuclei "$output_dir"
    db_print_summary

    log_success "[Agent] Done. Reports:"
    log_success "  Summary : $agent_summary"
    log_success "  Full log: $agent_log"
    log_success "  Tool out: $agent_tool_log"
    return 0
}

# ── Tool schema (what Claude sees) ────────────────────────────────────────────

_agent_tools_schema() {
    jq -n '
    [
      {
        name: "passive_recon",
        description: "Zero-packet passive recon via crt.sh, Shodan pre-indexed data, Wayback Machine, VirusTotal passive DNS, GitHub code search, WHOIS. No packets sent to target. Always run this first.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", description: "Domain to investigate" } },
          required: ["target"]
        }
      },
      {
        name: "enumerate_subdomains",
        description: "Active subdomain enumeration with subfinder, assetfinder, amass, crt.sh. Discovers all subdomains and identifies live hosts via httpx.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", description: "Base domain" } },
          required: ["target"]
        }
      },
      {
        name: "dns_recon",
        description: "DNS records (A/AAAA/MX/NS/TXT/SOA/CAA), zone transfer attempt (AXFR), DNSSEC validation, ASN lookup, wildcard DNS detection.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", description: "Domain name" } },
          required: ["target"]
        }
      },
      {
        name: "osint_lookup",
        description: "OSINT: Shodan host data, VirusTotal reputation, Censys, Have I Been Pwned domain breach check, git leak detection (trufflehog/gitleaks).",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", description: "Domain or IP address" } },
          required: ["target"]
        }
      },
      {
        name: "port_scan",
        description: "Port scan with nmap. CIDR targets trigger a ping sweep first. URL targets extract the hostname. Reveals open ports and service banners.",
        input_schema: {
          type: "object",
          properties: {
            target: { type: "string", description: "Domain, IP, CIDR, or URL" },
            mode: { type: "string", enum: ["light","medium","aggressive"], description: "Scan depth. Use light for wide/quick, medium for standard, aggressive for thorough single-host." }
          },
          required: ["target"]
        }
      },
      {
        name: "ssl_check",
        description: "TLS/SSL assessment: certificate validity and expiry, weak protocols/ciphers, HTTP security headers (HSTS/CSP/X-Frame-Options/CORS), SPF/DMARC/DKIM email security.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", description: "Domain or URL with HTTPS" } },
          required: ["target"]
        }
      },
      {
        name: "web_crawl",
        description: "Recursive web crawling. Discovers all URLs, API endpoints, JavaScript files, admin/login pages, and interesting file types. Uses katana, gospider, hakrawler, or built-in bash crawler.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", description: "Domain or URL to start crawling from" } },
          required: ["target"]
        }
      },
      {
        name: "web_test",
        description: "Web application security tests: directory brute-force (feroxbuster/dirsearch), SQLMap injection testing, Nikto scanner, XSS (dalfox), parameter discovery (arjun), WhatWeb fingerprinting.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", description: "Domain, IP, or URL" } },
          required: ["target"]
        }
      },
      {
        name: "api_security",
        description: "API security: discovers OpenAPI/Swagger endpoints (18 common paths), GraphQL introspection, scans JavaScript files for secrets (AWS/Stripe/GitHub keys, JWTs), tests SSRF vectors via cloud metadata endpoints.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", description: "Domain or URL" } },
          required: ["target"]
        }
      },
      {
        name: "vuln_scan",
        description: "Nuclei vulnerability scanner across all previously discovered assets and output files. Runs all applicable templates including CVE, misconfiguration, exposure, and technology-specific checks.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", description: "Primary target (nuclei uses all prior output files)" } },
          required: ["target"]
        }
      },
      {
        name: "cve_match",
        description: "Correlates technology fingerprints discovered by nmap/WhatWeb with CVEs from the NVD database. Identifies known exploitable vulnerabilities for the specific versions detected.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", description: "Target identifier for context" } },
          required: ["target"]
        }
      },
      {
        name: "cloud_scan",
        description: "Cloud misconfiguration discovery: S3/GCS/Azure Blob bucket enumeration using 30+ naming patterns, Kubernetes API server and kubelet exposure detection.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", description: "Domain or IP" } },
          required: ["target"]
        }
      },
      {
        name: "screenshot",
        description: "Capture visual screenshots of all discovered web targets using gowitness or EyeWitness. Generates an HTML gallery. Useful for identifying login panels, admin dashboards, application types at a glance.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", description: "Domain, IP, or URL" } },
          required: ["target"]
        },
        cache_control: { type: "ephemeral" }
      }
    ]'
}

# ── Filter tool output before sending to API ──────────────────────────────────
# Strips ExposureScopeX log prefix lines ([*]/[+]/[-]/[!]) — they are noise for
# Claude. Keeps actual findings: IPs, ports, domains, CVEs, HTTP data, errors.
_filter_for_api() {
    grep -v $'^\x1b' \
    | sed 's/\x1b\[[0-9;]*m//g' \
    | grep -Ev '^\[[\*\+\-!]\] |^={3,}|^-{3,}|^[[:space:]]*$'
}

# ── Tool execution dispatcher ──────────────────────────────────────────────────

_agent_execute_tool() {
    local tool_name=$1
    local tool_target=$2
    local output_dir=$3
    local tool_mode=${4:-""}

    # Enforce passive-only mode at dispatch level
    if [ "${RUN_PASSIVE:-false}" = true ]; then
        case "$tool_name" in
            port_scan|web_test|web_crawl|api_security|vuln_scan|cloud_scan|screenshot)
                echo "[PASSIVE-ONLY] Tool '$tool_name' is blocked in passive-only mode."
                return 0
                ;;
        esac
    fi

    # Override scan mode when agent requests a specific one
    [ -n "$tool_mode" ] && export MODE="$tool_mode"

    # Track which output file contains the key findings for this tool
    local key_file=""

    case "$tool_name" in
        passive_recon)
            run_passive_recon "$tool_target" "$output_dir"
            key_file="${output_dir}/passive_recon.txt"
            ;;
        enumerate_subdomains)
            run_enumeration "$tool_target" "$output_dir"
            key_file="${output_dir}/subdomains.txt"
            ;;
        dns_recon)
            run_dns_recon "$tool_target" "$output_dir"
            key_file="${output_dir}/dns_recon.txt"
            ;;
        osint_lookup)
            run_osint "$tool_target" "$output_dir"
            ;;
        port_scan)
            run_port_scan "$tool_target" "$output_dir"
            key_file="${output_dir}/nmap_scan.txt"
            ;;
        ssl_check)
            run_ssl_check "$tool_target" "$output_dir"
            key_file="${output_dir}/ssl_results.txt"
            ;;
        web_crawl)
            run_crawler "$tool_target" "$output_dir"
            key_file="${output_dir}/crawl_results.txt"
            ;;
        web_test)
            run_web_test "$tool_target" "$output_dir"
            ;;
        api_security)
            run_api_security "$tool_target" "$output_dir"
            key_file="${output_dir}/api_security.txt"
            ;;
        vuln_scan)
            run_vuln_scan "$tool_target" "$output_dir"
            key_file="${output_dir}/nuclei_results.txt"
            ;;
        cve_match)
            run_cve_match "$tool_target" "$output_dir"
            key_file="${output_dir}/cve_matches.txt"
            ;;
        cloud_scan)
            run_cloud_scan "$tool_target" "$output_dir"
            ;;
        screenshot)
            run_screenshots "$tool_target" "$output_dir"
            ;;
        *)
            echo "[Agent] Unknown tool: $tool_name"
            return 1
            ;;
    esac

    # Append the key findings file so Claude sees actual data, not just log lines
    if [ -n "$key_file" ] && [ -f "$key_file" ] && [ -s "$key_file" ]; then
        local line_count
        line_count=$(wc -l < "$key_file" 2>/dev/null || echo 0)
        echo ""
        echo "=== Key findings ($key_file — ${line_count} lines) ==="
        head -100 "$key_file"
        if [ "$line_count" -gt 100 ]; then
            echo "[... $((line_count - 100)) more lines in file]"
        fi
    fi
}
