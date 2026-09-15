#!/bin/bash

# Web Application Testing Module

web_tool_enabled() {
    local tool=$1
    local enabled_tools
    enabled_tools=$(printf '%s' "${EXPOSURESCOPEX_ENABLED_TOOLS:-}" | tr '[:upper:]' '[:lower:]')

    if [ -n "$enabled_tools" ]; then
        case ",${enabled_tools}," in
            *",${tool},"*) return 0 ;;
            *) return 1 ;;
        esac
    fi

    case "$tool" in
        arjun|nikto) [ "${MODE:-medium}" != "light" ] ;;
        ffuf) [ "${MODE:-medium}" = "aggressive" ] ;;
        *) return 0 ;;
    esac
}

run_web_test() {
    local target=$1
    local output_dir=$2
    log_info "Starting Web Application Testing..."

    # prepare list of http(s) URLs
    local -a urls=()
    if [ -f "$target" ]; then
        mapfile -t urls < "$target"
    else
        if validate_url "$target"; then
            urls=("$target")
        elif validate_domain "$target"; then
            urls=("http://$target" "https://$target")
        elif validate_ip "$target"; then
            urls=("http://$target" "https://$target")
        else
            log_error "Invalid web target: $target"
            return 1
        fi
    fi

    # Directory brute-force
    # Each URL gets its own per-URL file; results are also aggregated into
    # feroxbuster_results.txt so vuln_scan.sh can consume one file.
    if command -v feroxbuster &> /dev/null; then
        local ferox_agg="${output_dir}/feroxbuster_results.txt"
        : > "$ferox_agg"
        log_info "Running Feroxbuster..."
        for u in "${urls[@]}"; do
            local ferox_out="${output_dir}/feroxbuster_$(echo "$u" | md5sum | cut -d' ' -f1).txt"
            echo "=== $u ===" >> "$ferox_agg"
            run_tool "feroxbuster" "feroxbuster" -u "$u" --silent --auto-tune --output "$ferox_out" || \
                log_warn "feroxbuster failed on $u"
            [ -f "$ferox_out" ] && cat "$ferox_out" >> "$ferox_agg"
        done
    elif command -v dirsearch &> /dev/null; then
        local dirsearch_output="${output_dir}/dirsearch_results.txt"
        log_info "Running Dirsearch..."
        local temp_urls
        temp_urls=$(mktemp)
        register_cleanup "$temp_urls"
        printf '%s\n' "${urls[@]}" > "$temp_urls"
        run_tool "dirsearch" "dirsearch" -l "$temp_urls" --simple-report="$dirsearch_output" || \
            log_warn "dirsearch failed"
    else
        log_warn "No directory brute-force tool available"
    fi

    # Web crawling — per-URL files aggregated into katana_crawl.txt
    if [ -s "${output_dir}/crawl_results.txt" ]; then
        log_info "Reusing dedicated crawler results for web testing"
        cp "${output_dir}/crawl_results.txt" "${output_dir}/katana_crawl.txt"
    elif command -v katana &> /dev/null; then
        local katana_agg="${output_dir}/katana_crawl.txt"
        : > "$katana_agg"
        log_info "Running Katana crawler..."
        for u in "${urls[@]}"; do
            local katana_out="${output_dir}/katana_$(echo "$u" | md5sum | cut -d' ' -f1).txt"
            echo "=== $u ===" >> "$katana_agg"
            run_tool "katana" "katana" -u "$u" -silent -o "$katana_out" || \
                log_warn "katana failed on $u"
            [ -f "$katana_out" ] && cat "$katana_out" >> "$katana_agg"
        done
    fi

    if command -v ffuf &> /dev/null && web_tool_enabled "ffuf"; then
        local ffuf_wordlist="${FFUF_WORDLIST:-/app/worker/wordlists/common-web.txt}"
        if [ -f "$ffuf_wordlist" ]; then
            log_info "Running ffuf content discovery..."
            for u in "${urls[@]}"; do
                local ffuf_out="${output_dir}/ffuf_$(echo "$u" | md5sum | cut -d' ' -f1).json"
                run_tool "ffuf" "ffuf" \
                    -w "$ffuf_wordlist" \
                    -u "${u%/}/FUZZ" \
                    -ac \
                    -noninteractive \
                    -mc "200,204,301,302,307,401,403,405" \
                    -of json \
                    -o "$ffuf_out" || \
                    log_warn "ffuf failed on $u"
            done
        else
            log_warn "ffuf wordlist not found: $ffuf_wordlist"
        fi
    fi

    if command -v arjun &> /dev/null && web_tool_enabled "arjun"; then
        log_info "Running Arjun parameter discovery..."
        for u in "${urls[@]}"; do
            local arjun_out="${output_dir}/arjun_$(echo "$u" | md5sum | cut -d' ' -f1).json"
            local -a arjun_args=(-u "$u" -m GET -oJ "$arjun_out" -T 12)
            if [ "$STEALTH_MODE" = true ]; then
                arjun_args+=(--stable)
            else
                arjun_args+=(-t 6)
            fi
            run_tool "arjun" "arjun" "${arjun_args[@]}" || \
                log_warn "Arjun failed on $u"
        done
    fi

    # WhatWeb
    if command -v whatweb &> /dev/null; then
        log_info "Running WhatWeb..."
        for u in "${urls[@]}"; do
            run_tool "whatweb" "whatweb" -a 3 --log-verbose="${output_dir}/whatweb_$(echo "$u" | md5sum | cut -d' ' -f1).txt" "$u" || \
                log_warn "whatweb failed on $u"
        done
    fi

    # Payload-injection scanners are intentionally excluded. ExposureScopeX
    # performs only the bounded, GET-only checks in safe_web_validation.py.

    # Nikto
    if command -v nikto &> /dev/null && web_tool_enabled "nikto"; then
        log_info "Running Nikto..."
        for u in "${urls[@]}"; do
            run_tool "nikto" "nikto" -h "$u" -o "${output_dir}/nikto_$(echo "$u" | md5sum | cut -d' ' -f1).txt" || \
                log_warn "nikto failed on $u"
        done
    fi

    log_success "Web testing completed"
    return 0
}
