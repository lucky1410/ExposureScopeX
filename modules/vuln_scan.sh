#!/bin/bash

# Vulnerability Scanning Module

run_vuln_scan() {
    local target=$1
    local output_dir=$2
    local nuclei_output="${output_dir}/nuclei_results.txt"
    local nikto_output="${output_dir}/nikto_results.txt"

    log_info "Starting Vulnerability Scanning..."

    check_dependency "nuclei"
    check_dependency "nikto"

    # 1. Nuclei
    if command -v nuclei &> /dev/null; then
        log_info "Running Nuclei..."
        
        local nuclei_args="-o $nuclei_output"
        
        # Determine target input for nuclei
        if [ -f "$target" ]; then
             nuclei_args="$nuclei_args -l $target"
        else
            # If target is a domain, check for subdomains file
            local subdomains_file="${output_dir}/subdomains.txt"
            if [ -f "$subdomains_file" ] && [ -s "$subdomains_file" ]; then
                log_info "Using subdomains for Nuclei..."
                nuclei_args="$nuclei_args -l $subdomains_file"
            else
                nuclei_args="$nuclei_args -u $target"
            fi
        fi

        # Severity filtering based on mode?
        # For now, run standard templates
        nuclei $nuclei_args
        
        log_success "Nuclei scan complete. Results: $nuclei_output"
    fi

    # 2. Nikto (Targeting main domain or specific web ports)
    # Nikto is slow for many targets, maybe only run on main domain or if explicitly asked?
    # For this framework, let's run it on the main target if it's a domain.
    if command -v nikto &> /dev/null; then
        if [ ! -f "$target" ]; then # Only run on single domain target to avoid taking forever
            log_info "Running Nikto on $target..."
            nikto -h "$target" -output "$nikto_output"
            log_success "Nikto scan complete. Results: $nikto_output"
        else
            log_info "Skipping Nikto for file input (too slow)."
        fi
    fi
}
