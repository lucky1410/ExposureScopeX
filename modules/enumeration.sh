#!/bin/bash

# Enumeration Module

run_enumeration() {
    local domain=$1
    local output_dir=$2
    local subdomains_file="${output_dir}/subdomains.txt"
    local temp_file="${output_dir}/temp_subs.txt"

    log_info "Starting Passive Enumeration for $domain..."

    # Check Dependencies
    check_dependency "subfinder"
    check_dependency "assetfinder"
    # Amass is slow, maybe optional or check if installed
    # check_dependency "amass" 

    # 1. Subfinder
    if command -v subfinder &> /dev/null; then
        log_info "Running Subfinder..."
        subfinder -d "$domain" -silent >> "$temp_file"
    fi

    # 2. Assetfinder
    if command -v assetfinder &> /dev/null; then
        log_info "Running Assetfinder..."
        assetfinder --subs-only "$domain" >> "$temp_file"
    fi

    # 3. crt.sh (via curl)
    log_info "Scraping crt.sh..."
    curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> "$temp_file"

    # 4. Amass (Passive) - Optional due to speed
    if command -v amass &> /dev/null; then
        log_info "Running Amass (Passive)..."
        amass enum -passive -d "$domain" -silent >> "$temp_file"
    fi

    # 5. Gobuster DNS (Active)
    if command -v gobuster &> /dev/null; then
        log_info "Running Gobuster DNS Bruteforce..."
        # Need a wordlist. Check common locations or ask user?
        # For now, skip if no wordlist found or use a small default if available.
        # This is often slow, maybe only for aggressive mode?
        :
    fi

    # 6. Subdomain Takeover (Subjack)
    if check_dependency "subjack"; then
        log_info "Running Subjack for Subdomain Takeover..."
        # Requires a fingerprints file. Usually at /usr/share/subjack/fingerprints.json or similar.
        # We'll assume default or try to find it.
        local fingerprints="/usr/share/subjack/fingerprints.json"
        if [ ! -f "$fingerprints" ]; then
             # Try to download if missing? Or just warn.
             # For now, let's assume user has it or we skip.
             # Actually, let's try to fetch it if missing to be helpful.
             if check_dependency "wget"; then
                 wget -q -O "${CONFIG_DIR}/fingerprints.json" "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json"
                 fingerprints="${CONFIG_DIR}/fingerprints.json"
             fi
        fi
        
        if [ -f "$fingerprints" ]; then
            subjack -w "$subdomains_file" -t 100 -timeout 30 -o "${output_dir}/potential_takeovers.txt" -ssl -c "$fingerprints" -v
        else
            log_warn "Subjack fingerprints not found. Skipping."
        fi
    fi

    # 7. Live Host Probing (httpx)
    local live_hosts="${output_dir}/live_hosts.txt"
    if check_dependency "httpx"; then
        log_info "Probing for live hosts with httpx..."
        httpx -l "$subdomains_file" -silent -o "$live_hosts"
        log_success "Live hosts saved to: $live_hosts"
    else
        log_warn "httpx missing. Skipping live host probing."
        # Fallback: just copy subdomains if no httpx? No, better to know what's live.
    fi

    # 8. Historical URL Discovery (waybackurls / gau)
    local urls_file="${output_dir}/wayback_urls.txt"
    if check_dependency "waybackurls"; then
        log_info "Fetching historical URLs with waybackurls..."
        cat "$subdomains_file" | waybackurls > "$urls_file"
        log_success "Historical URLs saved to: $urls_file"
    elif check_dependency "gau"; then
        log_info "Fetching historical URLs with gau..."
        cat "$subdomains_file" | gau > "$urls_file"
        log_success "Historical URLs saved to: $urls_file"
    fi

    # Deduplicate and Sort
    if [ -f "$temp_file" ]; then
        sort -u "$temp_file" > "$subdomains_file"
        rm "$temp_file"
        local count=$(wc -l < "$subdomains_file")
        log_success "Enumeration complete. Found $count unique subdomains."
        log_info "Results saved to: $subdomains_file"
    else
        log_warn "No subdomains found."
        touch "$subdomains_file"
    fi
}
