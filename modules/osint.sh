#!/bin/bash

# OSINT Module

run_osint() {
    local target=$1
    local output_dir=$2
    local osint_output="${output_dir}/osint_results.txt"

    log_info "Starting OSINT Module..."

    # 1. Shodan
    if [ -n "$SHODAN_API_KEY" ]; then
        log_info "Querying Shodan..."
        check_dependency "shodan"
        # shodan init "$SHODAN_API_KEY" # Assume already init or do it here?
        # Better to use curl for API to avoid tool dependency issues
        curl -s "https://api.shodan.io/shodan/host/$target?key=$SHODAN_API_KEY" | jq . > "${output_dir}/shodan_data.json"
    else
        log_info "No Shodan API Key provided. Skipping."
    fi

    # 2. VirusTotal
    if [ -n "$VIRUSTOTAL_API_KEY" ]; then
        log_info "Querying VirusTotal..."
        curl -s --header "x-apikey: $VIRUSTOTAL_API_KEY" "https://www.virustotal.com/api/v3/domains/$target" | jq . > "${output_dir}/vt_data.json"
    fi

    # 3. Git Leaks / Trufflehog
    # These usually run on repos, but can run on URLs sometimes.
    # For a domain, maybe search github?
    # git-hound is good for this.
    if command -v git-hound &> /dev/null; then
        log_info "Running Git-Hound..."
        echo "$target" | git-hound >> "$osint_output"
    fi
}
