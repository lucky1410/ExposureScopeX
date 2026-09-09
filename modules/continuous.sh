#!/bin/bash

# Continuous Monitoring Module
# Manages state persistence, diff detection, and cron scheduling

STATE_DIR="${RESULTS_DIR}/state"

init_state_dir() {
    mkdir -p "$STATE_DIR"
}

get_state_file() {
    local target=$1
    local safe_name
    safe_name=$(sanitize_filename "$target")
    echo "${STATE_DIR}/${safe_name}.json"
}

# Save current scan results as a JSON state snapshot
save_state() {
    local target=$1
    local session_dir=$2

    if ! command -v jq &>/dev/null; then
        log_warn "jq required for state saving — skipping"
        return 1
    fi

    init_state_dir
    local state_file
    state_file=$(get_state_file "$target")

    local subdomains="[]" live_hosts="[]" open_ports="[]" vulns="[]"

    [ -f "${session_dir}/subdomains.txt" ] && \
        subdomains=$(jq -R . "${session_dir}/subdomains.txt" 2>/dev/null | jq -s 'map(select(length>0))' 2>/dev/null || echo "[]")

    [ -f "${session_dir}/live_hosts.txt" ] && \
        live_hosts=$(jq -R . "${session_dir}/live_hosts.txt" 2>/dev/null | jq -s 'map(select(length>0))' 2>/dev/null || echo "[]")

    if [ -f "${session_dir}/nmap_scan.txt" ]; then
        open_ports=$(grep -E "/tcp|/udp" "${session_dir}/nmap_scan.txt" 2>/dev/null | grep " open " | \
            jq -R . | jq -s 'map(select(length>0))' 2>/dev/null || echo "[]")
    fi

    [ -f "${session_dir}/nuclei_results.txt" ] && \
        vulns=$(jq -R . "${session_dir}/nuclei_results.txt" 2>/dev/null | jq -s 'map(select(length>0))' 2>/dev/null || echo "[]")

    jq -n \
        --arg target "$target" \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg session "$session_dir" \
        --argjson subdomains "$subdomains" \
        --argjson live_hosts "$live_hosts" \
        --argjson open_ports "$open_ports" \
        --argjson vulns "$vulns" \
        '{
            target: $target,
            timestamp: $timestamp,
            session: $session,
            subdomains: $subdomains,
            live_hosts: $live_hosts,
            open_ports: $open_ports,
            vulns: $vulns
        }' > "$state_file" 2>/dev/null && log_success "State saved: $state_file" || \
            log_warn "State save failed"
}

# Returns path to previous state file if it exists
load_previous_state() {
    local target=$1
    local state_file
    state_file=$(get_state_file "$target")
    [ -f "$state_file" ] && echo "$state_file" && return 0
    return 1
}

# Diff previous state against current session and write changes.md
diff_states() {
    local prev_state_file=$1
    local session_dir=$2
    local diff_output="${session_dir}/changes.md"

    if [ ! -f "$prev_state_file" ]; then
        log_info "No previous state — this is the baseline scan, no diff to compute"
        return 1
    fi

    log_info "Running change detection against previous scan..."
    local prev_ts
    prev_ts=$(jq -r '.timestamp // "unknown"' "$prev_state_file" 2>/dev/null)

    local any_changes=false

    # Helper: sorted lines from a file, filtered
    _sorted_file() { [ -f "$1" ] && sort "$1" || true; }

    local prev_subs current_subs prev_ports current_ports prev_vulns current_vulns

    prev_subs=$(jq -r '.subdomains[]?' "$prev_state_file" 2>/dev/null | sort)
    current_subs=$(_sorted_file "${session_dir}/subdomains.txt")

    prev_ports=$(jq -r '.open_ports[]?' "$prev_state_file" 2>/dev/null | sort)
    if [ -f "${session_dir}/nmap_scan.txt" ]; then
        current_ports=$(grep -E "/tcp|/udp" "${session_dir}/nmap_scan.txt" 2>/dev/null | grep " open " | sort)
    else
        current_ports=""
    fi

    prev_vulns=$(jq -r '.vulns[]?' "$prev_state_file" 2>/dev/null | sort)
    current_vulns=$(_sorted_file "${session_dir}/nuclei_results.txt")

    {
        echo "# Change Detection Report"
        echo ""
        echo "| | |"
        echo "|---|---|"
        echo "| **Previous Scan** | $prev_ts |"
        echo "| **Current Scan** | $(date -u +%Y-%m-%dT%H:%M:%SZ) |"
        echo ""

        # Subdomains
        echo "## Subdomains"
        echo ""
        local new_subs removed_subs
        new_subs=$(comm -13 <(echo "$prev_subs") <(echo "$current_subs") 2>/dev/null | grep -v '^$' || true)
        removed_subs=$(comm -23 <(echo "$prev_subs") <(echo "$current_subs") 2>/dev/null | grep -v '^$' || true)

        if [ -n "$new_subs" ]; then
            any_changes=true
            echo "### New"
            echo "$new_subs" | while IFS= read -r s; do echo "- \`$s\`"; done
            echo ""
        fi
        if [ -n "$removed_subs" ]; then
            any_changes=true
            echo "### Removed"
            echo "$removed_subs" | while IFS= read -r s; do echo "- \`$s\`"; done
            echo ""
        fi
        [ -z "$new_subs" ] && [ -z "$removed_subs" ] && echo "_No changes_" && echo ""

        # Open Ports
        echo "## Open Ports"
        echo ""
        local new_ports closed_ports
        new_ports=$(comm -13 <(echo "$prev_ports") <(echo "$current_ports") 2>/dev/null | grep -v '^$' || true)
        closed_ports=$(comm -23 <(echo "$prev_ports") <(echo "$current_ports") 2>/dev/null | grep -v '^$' || true)

        if [ -n "$new_ports" ]; then
            any_changes=true
            echo "### Newly Open"
            echo "$new_ports" | while IFS= read -r p; do echo "- \`$p\`"; done
            echo ""
        fi
        if [ -n "$closed_ports" ]; then
            echo "### Now Closed"
            echo "$closed_ports" | while IFS= read -r p; do echo "- \`$p\`"; done
            echo ""
        fi
        [ -z "$new_ports" ] && [ -z "$closed_ports" ] && echo "_No changes_" && echo ""

        # Vulnerabilities
        echo "## Vulnerabilities"
        echo ""
        local new_vulns resolved_vulns
        new_vulns=$(comm -13 <(echo "$prev_vulns") <(echo "$current_vulns") 2>/dev/null | grep -v '^$' || true)
        resolved_vulns=$(comm -23 <(echo "$prev_vulns") <(echo "$current_vulns") 2>/dev/null | grep -v '^$' || true)

        if [ -n "$new_vulns" ]; then
            any_changes=true
            echo "### New Findings"
            echo "$new_vulns" | while IFS= read -r v; do echo "- $v"; done
            echo ""
        fi
        if [ -n "$resolved_vulns" ]; then
            echo "### Resolved"
            echo "$resolved_vulns" | while IFS= read -r v; do echo "- $v"; done
            echo ""
        fi
        [ -z "$new_vulns" ] && [ -z "$resolved_vulns" ] && echo "_No changes_" && echo ""

        echo "---"
        if [ "$any_changes" = true ]; then
            echo "**Changes detected — review sections above.**"
        else
            echo "**No significant changes detected since last scan.**"
        fi
        echo ""
        echo "*ExposureScopeX Change Report*"

    } > "$diff_output"

    log_success "Change report: $diff_output"
    [ "$any_changes" = true ]
}

# Create/update a symlink: results/<safe_target>/latest -> <session_dir>
update_latest_symlink() {
    local target=$1
    local session_dir=$2
    local safe_name
    safe_name=$(sanitize_filename "$target")
    local link_dir="${RESULTS_DIR}/${safe_name}"
    mkdir -p "$link_dir"
    ln -sfn "$session_dir" "${link_dir}/latest"
    log_info "Latest results: ${link_dir}/latest"
}

# Register a cron job for continuous monitoring
setup_schedule() {
    local target=$1
    local cron_expr=$2
    local script_path="${SCRIPT_DIR}/exposurescopex.sh"

    if [ ! -x "$script_path" ]; then
        log_error "Script not executable: $script_path"
        return 1
    fi

    local cmd_args="-d $target -e -s -r --diff --auto"
    [ "${SLACK_NOTIFY:-false}" = true ]  && cmd_args+=" --slack"
    [ "${TEAMS_NOTIFY:-false}" = true ]  && cmd_args+=" --teams"
    [ "${SIEM_NOTIFY:-false}" = true ]   && cmd_args+=" --siem"

    local tag="# ExposureScopeX:$target"
    local entry="$cron_expr $script_path $cmd_args >> ${LOG_FILE} 2>&1"

    # Remove existing entry for this target then append new one
    {
        crontab -l 2>/dev/null | grep -v "ExposureScopeX:$target" | grep -v "$script_path.*-d $target "
        echo "$tag"
        echo "$entry"
    } | crontab -

    log_success "Scheduled: $cron_expr"
    log_info "  Command: $script_path $cmd_args"
    log_info "  Verify : crontab -l"
}

# Remove scheduled monitoring for a target
remove_schedule() {
    local target=$1
    local script_path="${SCRIPT_DIR}/exposurescopex.sh"

    if ! crontab -l 2>/dev/null | grep -q "ExposureScopeX:$target"; then
        log_warn "No schedule found for: $target"
        return 1
    fi

    {
        crontab -l 2>/dev/null | grep -v "ExposureScopeX:$target" | grep -v "$script_path.*-d $target "
    } | crontab -

    log_success "Schedule removed for: $target"
}

# List all active ExposureScopeX schedules
list_schedules() {
    log_info "Active ExposureScopeX schedules:"
    local schedules
    schedules=$(crontab -l 2>/dev/null | grep -A1 "ExposureScopeX:" | grep -v "^--$" || true)
    if [ -z "$schedules" ]; then
        echo "  (none)"
    else
        echo "$schedules"
    fi
}

# Convert an interval in hours to a cron expression (runs at 02:00 by default)
hours_to_cron() {
    local hours=$1
    case "$hours" in
        1)   echo "0 * * * *" ;;
        6)   echo "0 */6 * * *" ;;
        12)  echo "0 */12 * * *" ;;
        24)  echo "0 2 * * *" ;;
        48)  echo "0 2 */2 * *" ;;
        168) echo "0 2 * * 0" ;;   # weekly
        *)   echo "0 2 */${hours} * *" ;;
    esac
}
