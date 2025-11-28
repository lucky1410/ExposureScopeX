#!/bin/bash

# Web Application Testing Module

run_web_test() {
    local target=$1
    local output_dir=$2
    
    log_info "Starting Web Application Testing..."

    check_dependency "sqlmap"
    check_dependency "dirsearch"
    # check_dependency "xsstrike" # Often a python script, might not be in path

    # 1. Directory Bruteforce
    # Prefer Feroxbuster if available, else Dirsearch
    if check_dependency "feroxbuster"; then
        local ferox_output="${output_dir}/feroxbuster_results.txt"
        log_info "Running Feroxbuster..."
        # -u target, --silent, --no-state
        # If target is a file, we need a loop or feroxbuster's stdin mode? 
        # Feroxbuster takes -u or --stdin.
        if [ -f "$target" ]; then
             cat "$target" | feroxbuster --stdin --silent --extract-links --auto-tune --output "$ferox_output"
        else
             feroxbuster -u "$target" --silent --extract-links --auto-tune --output "$ferox_output"
        fi
        log_success "Feroxbuster complete."
    elif check_dependency "dirsearch"; then
        local dirsearch_output="${output_dir}/dirsearch_results.txt"
        log_info "Running Dirsearch..."
        
        if [ -f "$target" ]; then
             dirsearch -l "$target" --simple-report="$dirsearch_output"
        else
             dirsearch -u "$target" --simple-report="$dirsearch_output"
        fi
        log_success "Dirsearch complete."
    fi

    # 2. Crawling (Katana)
    if check_dependency "katana"; then
        local katana_output="${output_dir}/katana_crawl.txt"
        log_info "Running Katana Crawler..."
        if [ -f "$target" ]; then
            katana -list "$target" -o "$katana_output" -silent
        else
            katana -u "$target" -o "$katana_output" -silent
        fi
        log_success "Katana crawl complete."
    fi

    # 3. SQLMap
    # Only run if user explicitly asks or if we found parameters? 
    # For safety, maybe only run if -x (exploit) is NOT enabled but we want to check?
    # Actually, SQLMap is aggressive. Let's put it behind a check or only run crawl.
    if command -v sqlmap &> /dev/null; then
        if [ ! -f "$target" ]; then
            log_info "Running SQLMap (Crawl)..."
            # --batch for non-interactive
            # --crawl=1 to find URLs
            # --forms to parse forms
            # --level 1 --risk 1 (Safe)
            sqlmap -u "$target" --crawl=1 --batch --forms --level=1 --risk=1 --output-dir="${output_dir}/sqlmap"
        fi
    fi

    # 3. WhatWeb (Fingerprinting)
    if check_dependency "whatweb"; then
        log_info "Running WhatWeb..."
        whatweb -a 3 --log-verbose="${output_dir}/whatweb_results.txt" "$target"
    fi

    # 4. Wapiti (Web Vuln Scanner)
    if check_dependency "wapiti"; then
        log_info "Running Wapiti..."
        # -u for URL, --flush-session to force new scan
        wapiti -u "$target" --flush-session -o "${output_dir}/wapiti_report" -f html
    fi

    # 5. Dalfox (XSS)
    if check_dependency "dalfox"; then
        log_info "Running Dalfox (XSS)..."
        # Needs a list of URLs with parameters.
        # If we ran dirsearch or have wayback data, we should use that.
        # For now, let's try to find params using Arjun first or just scan the main target.
        dalfox url "$target" -o "${output_dir}/dalfox_xss.txt"
    fi

    # 6. Arjun (Parameter Discovery)
    if check_dependency "arjun"; then
        log_info "Running Arjun (Parameter Discovery)..."
        arjun -u "$target" -oT "${output_dir}/arjun_params.txt"
    fi

    # 7. XSStrike (Legacy/Alternative)
    # Implementation depends on how it's installed.
    :
}
