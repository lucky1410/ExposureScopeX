#!/bin/bash

# Enumeration Module

run_enumeration() {
    local domain=$1
    local output_dir=$2
    local subdomains_file="${output_dir}/subdomains.txt"
    local temp_file

    # validate domain
    if ! validate_domain "$domain"; then
        log_error "Invalid domain provided to enumeration: $domain"
        return 1
    fi

    log_info "Starting Passive Enumeration for $domain..."

    temp_file=$(mktemp -p "$output_dir" temp_subs.XXXXXX) || return 1
    register_cleanup "$temp_file"

    # Subfinder
    if command -v subfinder &> /dev/null; then
        log_info "Running Subfinder..."
        if ! run_tool "subfinder" "subfinder" -d "$domain" -silent >> "$temp_file"; then
            log_warn "Subfinder failed"
        fi
    fi

    # Assetfinder
    if command -v assetfinder &> /dev/null; then
        log_info "Running Assetfinder..."
        if ! run_tool "assetfinder" "assetfinder" --subs-only "$domain" >> "$temp_file"; then
            log_warn "Assetfinder failed"
        fi
    fi

    # crt.sh
    log_info "Scraping crt.sh..."
    if ! curl -s --max-time 30 "https://crt.sh/?q=%25.$domain&output=json" | \
         jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' >> "$temp_file"; then
        log_warn "crt.sh query failed"
    fi

    # Amass (optional)
    if [ "${MODE:-medium}" != "light" ] && command -v amass &> /dev/null; then
        log_info "Running Amass (Passive)"
        if ! run_tool "amass" "amass" enum -passive -d "$domain" -silent >> "$temp_file"; then
            log_warn "Amass failed"
        fi
    elif [ "${MODE:-medium}" = "light" ]; then
        log_info "Light mode: skipping Amass"
    fi

    # Deduplicate
    if [ -s "$temp_file" ]; then
        sort -u "$temp_file" > "$subdomains_file"
        rm -f "$temp_file"
        local count
        count=$(wc -l < "$subdomains_file")
        log_success "Enumeration complete. Found $count unique subdomains."
        log_info "Results saved to: $subdomains_file"
    else
        log_warn "No subdomains discovered"
        touch "$subdomains_file"
    fi

    # Subdomain takeover with subjack
    if [ "${MODE:-medium}" != "light" ] && command -v subjack &> /dev/null && [ -s "$subdomains_file" ]; then
        log_info "Checking for potential subdomain takeovers"
        # Current subjack embeds its fingerprints and no longer accepts -c.
        subjack -w "$subdomains_file" -t 100 -timeout 30 \
               -o "${output_dir}/potential_takeovers.txt" -ssl -v || \
            log_warn "subjack reported errors"
    fi

    # Live host probing
    local live_hosts="${output_dir}/live_hosts.txt"
    if command -v httpx &> /dev/null && [ -s "$subdomains_file" ]; then
        log_info "Probing live hosts"
        if ! run_tool "httpx" "httpx" -l "$subdomains_file" -silent -o "$live_hosts"; then
            log_warn "httpx probing failed"
            touch "$live_hosts"
        else
            log_success "Live hosts saved to: $live_hosts"
        fi
    else
        log_info "httpx not available or no subdomains, skipping live probe"
        touch "$live_hosts"
    fi

    # Historical URLs
    local urls_file="${output_dir}/wayback_urls.txt"
    if command -v waybackurls &> /dev/null && [ -s "$subdomains_file" ]; then
        log_info "Fetching historical URLs with waybackurls"
        if ! cat "$subdomains_file" | waybackurls > "$urls_file"; then
            log_warn "waybackurls failed"
            touch "$urls_file"
        fi
    elif command -v gau &> /dev/null && [ -s "$subdomains_file" ]; then
        log_info "Fetching historical URLs with gau"
        if ! cat "$subdomains_file" | gau > "$urls_file"; then
            log_warn "gau failed"
            touch "$urls_file"
        fi
    else
        touch "$urls_file"
    fi

    # Deduplicate URL file
    [ -f "$urls_file" ] && sort -u "$urls_file" -o "$urls_file"

    log_success "Enumeration module complete"
    return 0
}
