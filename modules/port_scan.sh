#!/bin/bash

# Port Scanning Module

run_port_scan() {
    local target=$1 # Can be domain or file
    local output_dir=$2
    local nmap_output="${output_dir}/nmap_scan.txt"
    local nmap_xml="${output_dir}/nmap_scan.xml"

    log_info "Starting Port Scanning..."

    check_dependency "nmap"

    local nmap_args=""

    case "$SCAN_SPEED" in
        light)
            log_info "Mode: Light (Top 100 ports, fast)"
            nmap_args="-F -T4 --open"
            ;;
        medium)
            log_info "Mode: Medium (Top 1000 ports, service detection)"
            nmap_args="-sV -sC -T4 --top-ports 1000 --open"
            ;;
        aggressive)
            log_info "Mode: Aggressive (All ports, OS detection, scripts)"
            nmap_args="-p- -sV -sC -O -T4 --open"
            ;;
        *)
            nmap_args="-sV -T4 --top-ports 1000"
            ;;
    esac

    # If target is a file, use -iL
    if [ -f "$target" ]; then
        log_info "Scanning targets from file: $target"
        nmap $nmap_args -iL "$target" -oN "$nmap_output" -oX "$nmap_xml"
    else
        # If target is a domain, check if we have subdomains from enumeration
        local subdomains_file="${output_dir}/subdomains.txt"
        if [ -f "$subdomains_file" ] && [ -s "$subdomains_file" ]; then
             log_info "Scanning subdomains from: $subdomains_file"
             nmap $nmap_args -iL "$subdomains_file" -oN "$nmap_output" -oX "$nmap_xml"
        else
             log_info "Scanning single target: $target"
             nmap $nmap_args "$target" -oN "$nmap_output" -oX "$nmap_xml"
        fi
    fi

    log_success "Port scanning complete."
    log_info "Results saved to: $nmap_output"
}
