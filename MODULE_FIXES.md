# ExposureScopeX - Module-by-Module Fixes

> Historical remediation notes. Do not apply these snippets blindly to the current v2.2 codebase.

This document provides specific code fixes for each module in the framework.

---

## Module: `modules/enumeration.sh`

### Current Issues:
1. No error checking on tool execution
2. Fragile output parsing with grep
3. Assumes tool availability without proper fallbacks
4. Temp file cleanup missing

### Fixed Version:

```bash
#!/bin/bash

##
# Enumeration Module - Passive and Active Subdomain Discovery
# Discovers subdomains using multiple sources with fallbacks
#

run_enumeration() {
    local domain=$1
    local output_dir=$2
    local subdomains_file="${output_dir}/subdomains.txt"
    local temp_file="${output_dir}/temp_subs_$$.txt"

    log_info "Starting Passive Enumeration for $domain..."

    # Register temp file for cleanup
    register_cleanup "$temp_file"

    # Validate domain
    if ! validate_domain "$domain"; then
        log_error "Invalid domain: $domain"
        return 1
    fi

    touch "$temp_file"
    local tools_run=0

    # 1. Subfinder (preferred, fastest)
    if command -v subfinder &> /dev/null; then
        log_info "Running Subfinder..."
        if subfinder -d "$domain" -silent >> "$temp_file" 2>/dev/null; then
            log_success "Subfinder completed"
            ((tools_run++))
        else
            log_warn "Subfinder failed (continuing with other tools)"
        fi
    else
        log_info "Subfinder not found (skipping)"
    fi

    # 2. Assetfinder
    if command -v assetfinder &> /dev/null; then
        log_info "Running Assetfinder..."
        if assetfinder --subs-only "$domain" >> "$temp_file" 2>/dev/null; then
            log_success "Assetfinder completed"
            ((tools_run++))
        else
            log_warn "Assetfinder failed (continuing)"
        fi
    fi

    # 3. crt.sh (Certificate transparency - reliable)
    log_info "Scraping crt.sh (Certificate Transparency)..."
    if curl -s "https://crt.sh/?q=%25.$domain&output=json" 2>/dev/null | \
       jq -r '.[].name_value' 2>/dev/null | \
       sed 's/\*\.//g' >> "$temp_file" 2>/dev/null; then
        log_success "crt.sh completed"
        ((tools_run++))
    else
        log_warn "crt.sh query failed"
    fi

    # 4. Amass (Passive) - Optional due to speed
    if command -v amass &> /dev/null; then
        log_info "Running Amass (Passive - may take 1-2 minutes)..."
        if amass enum -passive -d "$domain" -silent >> "$temp_file" 2>/dev/null; then
            log_success "Amass completed"
            ((tools_run++))
        else
            log_warn "Amass failed"
        fi
    fi

    # Check if we got any results
    if [ $tools_run -eq 0 ]; then
        log_error "No enumeration tools available. Installing minimum requirements..."
        run_tool "subfinder" "subfinder" || log_warn "Could not install subfinder"
    fi

    # Process and Deduplicate Subdomains
    if [ -f "$temp_file" ] && [ -s "$temp_file" ]; then
        # Clean empty lines, trim whitespace, deduplicate
        grep -v '^[[:space:]]*$' "$temp_file" | \
            sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
            sort -u > "$subdomains_file"

        rm "$temp_file"

        local count=$(wc -l < "$subdomains_file")
        log_success "Enumeration complete. Found $count unique subdomains."
        log_info "Results saved to: $subdomains_file"
    else
        log_warn "No subdomains found."
        touch "$subdomains_file"
        rm -f "$temp_file"
        return 1
    fi

    # 5. Subdomain Takeover Detection (Subjack)
    if command -v subjack &> /dev/null; then
        log_info "Running Subjack for Subdomain Takeover Detection..."

        # Find fingerprints file
        local fingerprints=""
        for path in /usr/share/subjack/fingerprints.json \
                    /opt/subjack/fingerprints.json \
                    "${CONFIG_DIR}/fingerprints.json"; do
            if [ -f "$path" ]; then
                fingerprints="$path"
                break
            fi
        done

        if [ -z "$fingerprints" ]; then
            log_info "Downloading subjack fingerprints..."
            if ! wget -q -O "${CONFIG_DIR}/fingerprints.json" \
                    "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json"; then
                log_warn "Could not download fingerprints"
            else
                fingerprints="${CONFIG_DIR}/fingerprints.json"
            fi
        fi

        if [ -f "$fingerprints" ]; then
            if subjack -w "$subdomains_file" -t 100 -timeout 30 \
                       -o "${output_dir}/potential_takeovers.txt" \
                       -c "$fingerprints" 2>/dev/null; then
                log_success "Subjack completed. Findings saved."
            else
                log_warn "Subjack scan failed"
            fi
        fi
    fi

    # 6. Live Host Probing (httpx)
    local live_hosts="${output_dir}/live_hosts.txt"
    if command -v httpx &> /dev/null; then
        log_info "Probing for live hosts with httpx..."
        if httpx -l "$subdomains_file" -silent -o "$live_hosts" 2>/dev/null; then
            local live_count=$(wc -l < "$live_hosts")
            log_success "Live hosts probing complete: $live_count found"
        else
            log_warn "httpx scanning failed"
            touch "$live_hosts"
        fi
    else
        log_info "httpx not found - skipping live host detection"
        touch "$live_hosts"
    fi

    # 7. Historical URL Discovery
    local urls_file="${output_dir}/wayback_urls.txt"

    if command -v waybackurls &> /dev/null; then
        log_info "Fetching historical URLs with waybackurls..."
        if cat "$subdomains_file" | waybackurls > "$urls_file" 2>/dev/null; then
            local url_count=$(wc -l < "$urls_file")
            log_success "Found $url_count historical URLs"
        else
            log_warn "waybackurls failed"
            touch "$urls_file"
        fi
    elif command -v gau &> /dev/null; then
        log_info "Fetching historical URLs with gau (GetAllUrls)..."
        if cat "$subdomains_file" | gau > "$urls_file" 2>/dev/null; then
            local url_count=$(wc -l < "$urls_file")
            log_success "Found $url_count historical URLs"
        else
            log_warn "gau failed"
            touch "$urls_file"
        fi
    else
        log_info "No URL archive tools found (waybackurls/gau)"
        touch "$urls_file"
    fi

    # Deduplicate URLs
    if [ -s "$urls_file" ]; then
        sort -u "$urls_file" -o "$urls_file"
    fi

    log_success "Enumeration module complete"
    return 0
}
```

---

## Module: `modules/port_scan.sh`

### Current Issues:
1. Command injection risk with $nmap_args
2. No error handling for masscan
3. Missing target validation
4. Unclear Masscan integration

### Fixed Version:

```bash
#!/bin/bash

##
# Port Scanning Module - Nmap and Masscan
#

run_port_scan() {
    local target=$1
    local output_dir=$2
    local nmap_output="${output_dir}/nmap_scan.txt"
    local nmap_xml="${output_dir}/nmap_scan.xml"

    log_info "Starting Port Scanning..."

    ensure_tool_installed "nmap" || return 1

    # Build Nmap arguments based on scan speed (safe array usage)
    local -a nmap_args=()

    case "$SCAN_SPEED" in
        light)
            log_info "Mode: Light (Top 100 ports, fast)"
            nmap_args=(-F -T4 --open)
            ;;
        medium)
            log_info "Mode: Medium (Top 1000 ports, service detection)"
            nmap_args=(-sV -sC -T4 --top-ports 1000 --open)
            ;;
        aggressive)
            log_info "Mode: Aggressive (All ports, OS detection, scripts)"
            nmap_args=(-p- -sV -sC -O -T4 --open)
            ;;
        *)
            log_warn "Unknown scan speed: $SCAN_SPEED. Using medium."
            nmap_args=(-sV -T4 --top-ports 1000)
            ;;
    esac

    # Build target list
    local -a scan_targets=()

    if [ -f "$target" ]; then
        # Validate target file
        if ! validate_file "$target"; then
            return 1
        fi
        mapfile -t scan_targets < "$target"
        log_info "Scanning targets from file: $target"
    else
        # Validate domain
        if ! validate_domain "$target" && ! validate_ip "$target"; then
            log_error "Invalid target format: $target"
            return 1
        fi
        scan_targets=("$target")
        log_info "Scanning single target: $target"
    fi

    # Optional: Masscan pre-scan for fast port discovery
    if command -v masscan &> /dev/null && [ ${#scan_targets[@]} -eq 1 ]; then
        log_info "Attempting Masscan pre-scan..."

        local masscan_output="${output_dir}/masscan_results.txt"
        local masscan_cmd=("masscan" "-p1-65535" "--rate=1000" "--wait=0"
                          -oL "$masscan_output" "${scan_targets[@]}")

        # Check if we have permissions (Masscan needs root)
        if [ "$EUID" -ne 0 ] && ! sudo -l masscan &>/dev/null 2>&1; then
            log_warn "Masscan requires root/sudo. Skipping pre-scan."
        else
            log_info "Running: masscan ${masscan_cmd[*]:1}"

            if [ "$EUID" -ne 0 ]; then
                sudo "${masscan_cmd[@]}" 2>/dev/null || log_warn "Masscan failed"
            else
                "${masscan_cmd[@]}" 2>/dev/null || log_warn "Masscan failed"
            fi

            # Parse results if successful
            if [ -f "$masscan_output" ] && [ -s "$masscan_output" ]; then
                # Extract unique ports
                local masscan_ports=$(grep "open tcp" "$masscan_output" | \
                                     cut -d' ' -f3 | sort -u | paste -sd ',' -)

                if [ -n "$masscan_ports" ]; then
                    log_info "Masscan found open ports: $masscan_ports"
                    nmap_args=(-p"$masscan_ports" -sV -sC -T4 --open)
                    log_info "Nmap will scan only discovered ports"
                fi
            fi
        fi
    fi

    # Run Nmap
    log_info "Running Nmap with ${#nmap_args[@]} arguments..."

    if nmap "${nmap_args[@]}" -oN "$nmap_output" -oX "$nmap_xml" "${scan_targets[@]}" 2>&1 | \
       tee -a "${LOG_FILE}"; then
        log_success "Port scanning complete"
        log_info "Results saved to: $nmap_output"
        return 0
    else
        log_error "Nmap scan failed with exit code $?"
        return 1
    fi
}
```

---

## Module: `modules/web_test.sh`

### Current Issues:
1. File vs URL target handling inconsistent
2. No validation on targets
3. Tool availability checks scattered
4. SQLMap running on domains (should be URLs only)

### Fixed Version:

```bash
#!/bin/bash

##
# Web Application Testing Module
#

run_web_test() {
    local target=$1
    local output_dir=$2

    log_info "Starting Web Application Testing..."

    # Convert single domain to URL for web tools
    local -a web_targets=()

    if [ -f "$target" ]; then
        # File with URLs
        mapfile -t web_targets < "$target"
    else
        # Single domain - convert to HTTP URL
        if validate_domain "$target"; then
            web_targets=("http://$target" "https://$target")
        elif validate_url "$target"; then
            web_targets=("$target")
        else
            log_error "Invalid target for web testing: $target"
            return 1
        fi
    fi

    log_info "Web targets: ${#web_targets[@]} targets found"

    # 1. Directory Bruteforcing
    run_directory_bruteforce "$output_dir" "${web_targets[@]}" || true

    # 2. Web Crawling
    run_web_crawl "$output_dir" "${web_targets[@]}" || true

    # 3. Technology Fingerprinting
    run_fingerprinting "$output_dir" "${web_targets[@]}" || true

    # 4. Parameter Discovery
    run_parameter_discovery "$output_dir" "${web_targets[@]}" || true

    # 5. Web Vulnerability Scanning
    run_web_scanning "$output_dir" "${web_targets[@]}" || true

    log_success "Web Application Testing complete"
    return 0
}

##
# Directory Bruteforce with fallback
##
run_directory_bruteforce() {
    local output_dir=$1
    shift
    local -a targets=("$@")

    if command -v feroxbuster &> /dev/null; then
        local ferox_output="${output_dir}/feroxbuster_results.txt"
        log_info "Running Feroxbuster (directory bruteforce)..."

        for target in "${targets[@]}"; do
            if validate_url "$target"; then
                if feroxbuster -u "$target" --silent --auto-tune \
                              --output "$ferox_output" 2>/dev/null; then
                    log_success "Feroxbuster completed on $target"
                else
                    log_warn "Feroxbuster failed on $target"
                fi
            fi
        done
    elif command -v dirsearch &> /dev/null; then
        local dirsearch_output="${output_dir}/dirsearch_results.txt"
        log_info "Running Dirsearch (directory bruteforce)..."

        # Create temp file with URLs
        local temp_urls="${output_dir}/temp_urls_$$.txt"
        for target in "${targets[@]}"; do
            echo "$target" >> "$temp_urls"
        done

        if dirsearch -l "$temp_urls" --simple-report="$dirsearch_output" \
                     2>/dev/null; then
            log_success "Dirsearch completed"
        else
            log_warn "Dirsearch failed"
        fi

        rm -f "$temp_urls"
    else
        log_warn "No directory bruteforce tool found (feroxbuster/dirsearch)"
    fi
}

##
# Web Crawling
##
run_web_crawl() {
    local output_dir=$1
    shift
    local -a targets=("$@")

    if ! command -v katana &> /dev/null; then
        log_info "Katana not found - skipping web crawling"
        return 0
    fi

    local katana_output="${output_dir}/katana_crawl.txt"
    log_info "Running Katana Web Crawler..."

    for target in "${targets[@]}"; do
        if validate_url "$target"; then
            if katana -u "$target" -silent -o "$katana_output" 2>/dev/null; then
                log_success "Katana completed on $target"
            else
                log_warn "Katana failed on $target (continuing)"
            fi
        fi
    done
}

##
# Technology Fingerprinting
##
run_fingerprinting() {
    local output_dir=$1
    shift
    local -a targets=("$@")

    if ! command -v whatweb &> /dev/null; then
        log_info "WhatWeb not found"
        return 0
    fi

    log_info "Running WhatWeb (Technology Fingerprinting)..."

    for target in "${targets[@]}"; do
        if validate_url "$target"; then
            local whatweb_output="${output_dir}/whatweb_results_$(md5sum <<< "$target" | cut -d' ' -f1).txt"
            if whatweb -a 3 --log-verbose="$whatweb_output" "$target" 2>/dev/null; then
                log_success "WhatWeb completed on $target"
            else
                log_warn "WhatWeb failed on $target"
            fi
        fi
    done
}

##
# Parameter Discovery
##
run_parameter_discovery() {
    local output_dir=$1
    shift
    local -a targets=("$@")

    if ! command -v arjun &> /dev/null; then
        log_info "Arjun not found - skipping parameter discovery"
        return 0
    fi

    log_info "Running Arjun (Parameter Discovery)..."

    for target in "${targets[@]}"; do
        if validate_url "$target"; then
            local arjun_output="${output_dir}/arjun_params_$(md5sum <<< "$target" | cut -d' ' -f1).txt"
            if arjun -u "$target" -oT "$arjun_output" 2>/dev/null; then
                log_success "Arjun completed on $target"
            else
                log_warn "Arjun failed on $target"
            fi
        fi
    done
}

##
# Web Vulnerability Scanning
##
run_web_scanning() {
    local output_dir=$1
    shift
    local -a targets=("$@")

    # SQLMap (SQL Injection testing)
    if command -v sqlmap &> /dev/null; then
        log_info "Running SQLMap (SQL Injection testing)..."
        for target in "${targets[@]}"; do
            if validate_url "$target"; then
                log_info "  Testing: $target"
                sqlmap -u "$target" --crawl=1 --batch --forms \
                       --level=1 --risk=1 \
                       --output-dir="${output_dir}/sqlmap_$(md5sum <<< "$target" | cut -d' ' -f1)" \
                       2>/dev/null || log_warn "SQLMap failed on $target"
            fi
        done
    fi

    # XSS Detection (Dalfox)
    if command -v dalfox &> /dev/null; then
        log_info "Running Dalfox (XSS Detection)..."
        for target in "${targets[@]}"; do
            if validate_url "$target"; then
                if dalfox url "$target" -o "${output_dir}/dalfox_xss_$(md5sum <<< "$target" | cut -d' ' -f1).txt" \
                            2>/dev/null; then
                    log_success "Dalfox completed on $target"
                fi
            fi
        done
    fi

    # Nikto (Web Server Scanner)
    if command -v nikto &> /dev/null; then
        log_info "Running Nikto (Web Server Scanner)..."
        for target in "${targets[@]}"; do
            if validate_url "$target"; then
                if nikto -h "$target" -o "${output_dir}/nikto_$(md5sum <<< "$target" | cut -d' ' -f1).txt" \
                        2>/dev/null; then
                    log_success "Nikto completed on $target"
                fi
            fi
        done
    fi
}
```

---

## Module: `modules/integrations.sh`

### Current Issues:
1. No error handling for failed notifications
2. Credentials in plain text (API tokens)
2. Webhook payload is too simple

### Fixed Version:

```bash
#!/bin/bash

##
# Integrations Module - Slack, Teams, SIEM notifications
#

##
# Send Slack notification with attachments
##
send_slack_notification() {
    local message=$1
    local file_path=${2:-}

    if [ "$SLACK_NOTIFY" != true ] || [ -z "$SLACK_WEBHOOK_URL" ]; then
        return 0
    fi

    log_info "Sending Slack Notification..."

    # Build JSON payload
    local json_payload=$(cat <<EOF
{
    "text": "$message",
    "attachments": [
        {
            "color": "#36a64f",
            "title": "ExposureScopeX Report",
            "title_link": "file://$file_path",
            "text": "Scan report available",
            "mrkdwn_in": ["text"]
        }
    ]
}
EOF
)

    if curl -s -X POST \
            -H 'Content-type: application/json' \
            --data "$json_payload" \
            "$SLACK_WEBHOOK_URL" 2>/dev/null | grep -q "ok"; then
        log_success "Slack notification sent"
        return 0
    else
        log_error "Failed to send Slack notification"
        return 1
    fi
}

##
# Send Microsoft Teams notification
##
send_teams_notification() {
    local message=$1
    local severity=${2:-info}  # info, warning, error, critical

    if [ "$TEAMS_NOTIFY" != true ] || [ -z "$TEAMS_WEBHOOK_URL" ]; then
        return 0
    fi

    log_info "Sending Microsoft Teams Notification..."

    # Determine color based on severity
    local color="0078D4"  # Default blue
    case "$severity" in
        critical) color="C50F1F" ;;  # Red
        error)    color="E81B23" ;;  # Dark red
        warning)  color="FFB900" ;;  # Orange
        info)     color="0078D4" ;;  # Blue
    esac

    local teams_payload=$(cat <<EOF
{
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    "themeColor": "$color",
    "summary": "ExposureScopeX Report",
    "sections": [
        {
            "activityTitle": "ExposureScopeX Scan Report",
            "activitySubtitle": "Security Assessment Results",
            "text": "$message",
            "facts": [
                {
                    "name": "Framework",
                    "value": "ExposureScopeX 1.0"
                },
                {
                    "name": "Timestamp",
                    "value": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
                }
            ]
        }
    ]
}
EOF
)

    if curl -s -X POST \
            -H 'Content-Type: application/json' \
            --data "$teams_payload" \
            "$TEAMS_WEBHOOK_URL" 2>/dev/null | grep -q "1"; then
        log_success "Teams notification sent"
        return 0
    else
        log_error "Failed to send Teams notification"
        return 1
    fi
}

##
# Send logs to SIEM (Splunk HEC or Syslog)
##
send_siem_log() {
    local log_entry=$1
    local severity=${2:-INFO}

    if [ "$SIEM_NOTIFY" != true ]; then
        return 0
    fi

    log_info "Sending events to SIEM..."

    # Splunk HTTP Event Collector
    if [ -n "$SPLUNK_HEC_URL" ] && [ -n "$SPLUNK_HEC_TOKEN" ]; then
        local splunk_payload=$(cat <<EOF
{
    "event": "$log_entry",
    "sourcetype": "exposurescopex",
    "source": "exposurescopex:framework",
    "severity": "$severity"
}
EOF
)

        if curl -s -k \
                -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
                -H "Content-Type: application/json" \
                -d "$splunk_payload" \
                "$SPLUNK_HEC_URL" 2>/dev/null | grep -q "success"; then
            log_success "Event sent to Splunk"
        else
            log_error "Failed to send event to Splunk"
        fi
    fi

    # Syslog fallback
    if command -v logger &> /dev/null; then
        logger -t ExposureScopeX -p "security.${severity,,}" "$log_entry" 2>/dev/null || true
    fi

    return 0
}

##
# Secure notification only if configured
##
notify_if_configured() {
    local message=$1
    local file_path=${2:-}

    local notification_sent=0

    if [ "$SLACK_NOTIFY" = true ]; then
        send_slack_notification "$message" "$file_path" && ((notification_sent=1))
    fi

    if [ "$TEAMS_NOTIFY" = true ]; then
        send_teams_notification "$message" "info" && ((notification_sent=1))
    fi

    if [ "$SIEM_NOTIFY" = true ]; then
        send_siem_log "$message" "INFO" && ((notification_sent=1))
    fi

    if [ $notification_sent -eq 0 ] && [ "$SLACK_NOTIFY" != true ] && \
       [ "$TEAMS_NOTIFY" != true ] && [ "$SIEM_NOTIFY" != true ]; then
        log_info "No notifications configured (use --slack, --teams, or --siem flags)"
    fi

    return 0
}
```

---

## Module: `modules/utils.sh` - Key Additions

Add these security and validation functions:

```bash
#!/bin/bash

# ... existing code ...

##
# Array-based logging for sensitive operations
##
# log_operation: Logs operation details without exposing secrets
##
log_operation() {
    local operation=$1
    shift
    local -a args=("$@")

    # Mask sensitive arguments
    local masked_args=()
    for arg in "${args[@]}"; do
        if [[ "$arg" =~ ^(key|token|password|secret|auth)= ]]; then
            masked_args+=("[REDACTED]")
        else
            masked_args+=("$arg")
        fi
    done

    log_info "Operation: $operation ${masked_args[*]}"
}

##
# Validate API key format (basic)
##
validate_api_key() {
    local key=$1
    local key_name=$2

    if [ -z "$key" ]; then
        log_warn "No $key_name provided (some features will be unavailable)"
        return 1
    fi

    if [ ${#key} -lt 10 ]; then
        log_error "Invalid API key for $key_name (too short)"
        return 1
    fi

    return 0
}

##
# Verify required API keys at startup
##
verify_api_keys() {
    log_info "Verifying API keys..."

    local missing_keys=()

    if [ -z "$SHODAN_API_KEY" ]; then
        missing_keys+=("SHODAN_API_KEY")
    fi

    if [ -z "$VIRUSTOTAL_API_KEY" ]; then
        missing_keys+=("VIRUSTOTAL_API_KEY")
    fi

    if [ ${#missing_keys[@]} -gt 0 ]; then
        log_warn "Missing API keys: ${missing_keys[*]}"
        log_info "Set these as environment variables: export KEY_NAME=value"
        return 1
    fi

    return 0
}

##
# Create secure temp directory
##
create_temp_dir() {
    local temp_dir=$(mktemp -d)
    chmod 700 "$temp_dir"
    echo "$temp_dir"
}

##
# Safely remove sensitive files
##
secure_delete() {
    local file=$1

    if [ -f "$file" ]; then
        # Overwrite before deleting (basic security)
        if command -v shred &> /dev/null; then
            shred -vfz -n 3 "$file"
        else
            # Fallback if shred not available
            cat /dev/zero > "$file" 2>/dev/null
            rm -f "$file"
        fi
    fi
}

##
# Sanitize filename to prevent injection
##
sanitize_filename() {
    local filename=$1
    # Keep only alphanumeric, dots, dashes, underscores
    echo "$filename" | sed 's/[^a-zA-Z0-9._-]/_/g'
}

##
# Validate and sanitize domain list from file
##
validate_domain_list() {
    local file=$1
    local valid_domains=()

    if ! [ -f "$file" ]; then
        return 1
    fi

    while IFS= read -r domain; do
        # Skip comments and empty lines
        [[ "$domain" =~ ^#.*$ ]] && continue
        [[ -z "$domain" ]] && continue

        # Trim whitespace
        domain=$(echo "$domain" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        if validate_domain "$domain"; then
            valid_domains+=("$domain")
        else
            log_warn "Invalid domain in file: $domain"
        fi
    done < "$file"

    # Return via stdout
    printf '%s\n' "${valid_domains[@]}"
}
```

---

These module fixes should be applied incrementally and tested after each change.
