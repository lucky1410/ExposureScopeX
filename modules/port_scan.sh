#!/bin/bash

# Port Scanning Module

run_port_scan() {
    local target=$1
    local output_dir=$2
    local nmap_output="${output_dir}/nmap_scan.txt"
    local nmap_xml="${output_dir}/nmap_scan.xml"

    log_info "Starting Port Scanning..."

    # ── Detect target type and pre-process ────────────────────────────────
    local target_type
    target_type=$(detect_target_type "$target" 2>/dev/null || echo "unknown")

    case "$target_type" in
        cidr)
            # Host discovery sweep: discover live IPs before port scanning
            log_info "CIDR target ($target) — running host discovery sweep..."
            local sweep_file="${output_dir}/sweep_live_hosts.txt"
            if ! command -v nmap &>/dev/null; then
                log_error "nmap required for CIDR host discovery"
                return 1
            fi
            nmap -sn "$target" -oG - 2>/dev/null | awk '/Up$/{print $2}' > "$sweep_file"
            local live_count
            live_count=$(wc -l < "$sweep_file" 2>/dev/null || echo 0)
            if [ "$live_count" -eq 0 ]; then
                log_warn "No live hosts found in $target — skipping port scan"
                return 0
            fi
            log_success "Discovered $live_count live hosts in $target"
            # Merge into live_hosts.txt so web/API phases can pick them up
            cat "$sweep_file" >> "${output_dir}/live_hosts.txt"
            target="$sweep_file"
            target_type="file"
            ;;
        url)
            # Extract the hostname portion for port scanning
            local url_host
            url_host=$(echo "$target" | sed -E 's|^https?://([^/:]+).*|\1|')
            log_info "URL target — scanning extracted host: $url_host"
            target="$url_host"
            target_type=$(detect_target_type "$url_host" 2>/dev/null || echo "domain")
            ;;
        domain|ip|file)
            ;;   # no pre-processing needed
        *)
            log_error "Invalid scan target: $target"
            return 1
            ;;
    esac

    # ── Determine targets list ─────────────────────────────────────────────
    local -a scan_targets=()
    if [ -f "$target" ]; then
        mapfile -t scan_targets < "$target"
    else
        # For domain targets, prefer the subdomains file produced by enumeration
        local sub_file="${output_dir}/subdomains.txt"
        if [ "$target_type" = "domain" ] && [ -f "$sub_file" ] && [ -s "$sub_file" ]; then
            mapfile -t scan_targets < "$sub_file"
            log_info "Using subdomains from $sub_file"
        else
            scan_targets=("$target")
            log_info "Scanning single target: $target"
        fi
    fi

    # Sync MODE → SCAN_SPEED (MODE is set by the -m CLI flag)
    local effective_speed="${MODE:-${SCAN_SPEED:-medium}}"

    # configure nmap args
    local -a nmap_args=()
    case "$effective_speed" in
        light)
            nmap_args=(-F -T4 --open)
            ;;
        medium)
            nmap_args=(-sV -sC -T4 --top-ports 1000 --open)
            ;;
        aggressive)
            nmap_args=(-p- -sV -sC -O -T4 --open)
            ;;
        *)
            nmap_args=(-sV -T4 --top-ports 1000)
            ;;
    esac

    # optional masscan pre-scan when single host
    if command -v masscan &> /dev/null && [ ${#scan_targets[@]} -eq 1 ]; then
        log_info "Masscan available; running pre-scan"
        local masscan_output="${output_dir}/masscan_results.txt"
        local masscan_ports=""
        if [ "$EUID" -ne 0 ]; then
            if ! sudo -v &>/dev/null; then
                log_warn "No sudo privileges for masscan; skipping masscan"
            else
                sudo masscan -p1-65535 --rate=1000 --wait=0 "${scan_targets[0]}" -oL "$masscan_output" || true
            fi
        else
            masscan -p1-65535 --rate=1000 --wait=0 "${scan_targets[0]}" -oL "$masscan_output" || true
        fi
        if [ -f "$masscan_output" ]; then
            masscan_ports=$(grep "open tcp" "$masscan_output" | awk '{print $3}' | sort -u | paste -sd ',' -)
            if [ -n "$masscan_ports" ]; then
                log_info "Masscan found ports: $masscan_ports"
                nmap_args=(-p"$masscan_ports" -sV -sC -T4 --open)
            fi
        fi
    fi

    # Large imported inventories must not be one all-or-nothing Nmap process.
    # Preserve every completed batch so interruption or timeout does not discard
    # results from targets that have already finished.
    local batch_size=25
    [ "$effective_speed" = "light" ] && batch_size=100
    [ "$effective_speed" = "aggressive" ] && batch_size=5
    nmap_args+=(--host-timeout "${NMAP_HOST_TIMEOUT:-10m}" --max-retries "${NMAP_MAX_RETRIES:-2}")

    if [ ${#scan_targets[@]} -le "$batch_size" ]; then
        if ! run_tool "nmap" "nmap" "${nmap_args[@]}" -oN "$nmap_output" -oX "$nmap_xml" "${scan_targets[@]}"; then
            log_error "Nmap scan failed"
            return 1
        fi
    else
        : > "$nmap_output"
        local batch_number=0
        local completed_batches=0
        local offset
        for ((offset=0; offset<${#scan_targets[@]}; offset+=batch_size)); do
            batch_number=$((batch_number + 1))
            local -a batch_targets=("${scan_targets[@]:offset:batch_size}")
            local batch_base
            batch_base=$(printf '%s/nmap_scan_%03d' "$output_dir" "$batch_number")
            log_info "Nmap batch $batch_number: ${#batch_targets[@]} target(s)"
            if run_tool "nmap" "nmap" "${nmap_args[@]}" \
                -oN "${batch_base}.txt" -oX "${batch_base}.xml" "${batch_targets[@]}"; then
                cat "${batch_base}.txt" >> "$nmap_output"
                completed_batches=$((completed_batches + 1))
            else
                log_warn "Nmap batch $batch_number failed; continuing with remaining targets"
            fi
        done
        if [ "$completed_batches" -eq 0 ]; then
            log_error "All Nmap batches failed"
            return 1
        fi
        log_success "Nmap completed $completed_batches of $batch_number batches"
    fi

    log_success "Port scanning complete. Results: $nmap_output"
    return 0
}
