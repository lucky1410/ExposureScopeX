#!/bin/bash

# Web Crawler Module
# Recursively discovers URLs, forms, API endpoints, and JS files.
#
# Tool priority:
#   1. katana   — JS-aware, headless browser, best coverage  (ProjectDiscovery, open-source)
#   2. gospider — fast recursive spider                       (jaeles-project, open-source)
#   3. hakrawler — pipe-friendly minimal crawler             (hakluke, open-source)
#   4. _bash_crawl — zero-dependency built-in fallback       (curl + grep)

run_crawler() {
    local target=$1
    local output_dir=$2
    local crawl_out="${output_dir}/crawl_results.txt"
    : > "$crawl_out"

    # ── Resolve target to a URL list ──────────────────────────────────────
    local -a start_urls=()
    local ttype
    ttype=$(detect_target_type "$target" 2>/dev/null)
    case "$ttype" in
        url)    start_urls=("$target") ;;
        domain) start_urls=("http://$target" "https://$target") ;;
        ip)     start_urls=("http://$target" "https://$target") ;;
        file)
            # Use live_hosts or the file itself as a URL list
            if [ -s "${output_dir}/live_hosts.txt" ]; then
                mapfile -t start_urls < "${output_dir}/live_hosts.txt"
            else
                mapfile -t start_urls < "$target"
            fi
            ;;
        *)
            log_error "Crawler: unsupported target type '$ttype' for $target"
            return 1
            ;;
    esac

    log_info "Starting web crawler for ${#start_urls[@]} URL(s)..."

    if command -v katana &>/dev/null; then
        _crawl_katana start_urls "$crawl_out"
    elif command -v gospider &>/dev/null; then
        _crawl_gospider start_urls "$crawl_out"
    elif command -v hakrawler &>/dev/null; then
        _crawl_hakrawler start_urls "$crawl_out"
    else
        log_info "No external crawler found — using built-in bash crawler"
        log_info "  Install katana: go install github.com/projectdiscovery/katana/cmd/katana@latest"
        _crawl_bash start_urls "$crawl_out"
    fi

    # ── Post-processing: extract interesting findings ──────────────────────
    _extract_crawler_intel "$crawl_out" "$output_dir"

    local total
    total=$(wc -l < "$crawl_out" 2>/dev/null || echo 0)
    log_success "Crawler complete: $total URLs discovered → $crawl_out"
    return 0
}

# ── Tool wrappers ──────────────────────────────────────────────────────────────

_crawl_katana() {
    local -n _urls=$1
    local out=$2
    log_info "Crawler: katana (JS-aware)"
    for u in "${_urls[@]}"; do
        run_tool "katana" "katana" \
            -u "$u" \
            -d 3 \
            -silent \
            -jc \
            -o "${out}.katana_tmp" 2>/dev/null || log_warn "katana failed on $u"
        [ -f "${out}.katana_tmp" ] && cat "${out}.katana_tmp" >> "$out" && rm -f "${out}.katana_tmp"
    done
}

_crawl_gospider() {
    local -n _urls=$1
    local out=$2
    log_info "Crawler: gospider"
    for u in "${_urls[@]}"; do
        run_tool "gospider" "gospider" \
            -s "$u" \
            -d 3 \
            -c 10 \
            --include-subs \
            -q \
            -o "${out}.gospider_tmp" 2>/dev/null || log_warn "gospider failed on $u"
        if [ -d "${out}.gospider_tmp" ]; then
            find "${out}.gospider_tmp" -type f | xargs grep -hE '^https?://' >> "$out" 2>/dev/null || true
            rm -rf "${out}.gospider_tmp"
        fi
    done
}

_crawl_hakrawler() {
    local -n _urls=$1
    local out=$2
    log_info "Crawler: hakrawler"
    for u in "${_urls[@]}"; do
        echo "$u" | run_tool "hakrawler" "hakrawler" \
            -d 3 \
            -subs >> "$out" 2>/dev/null || log_warn "hakrawler failed on $u"
    done
}

# ── Built-in bash recursive crawler ───────────────────────────────────────────
# Uses only curl + standard POSIX utilities — zero external dependencies.
# Stays on the same domain, respects depth and page limits.

CRAWL_MAX_DEPTH=${CRAWL_MAX_DEPTH:-3}
CRAWL_MAX_PAGES=${CRAWL_MAX_PAGES:-300}
CRAWL_TIMEOUT=${CRAWL_TIMEOUT:-10}  # curl per-page timeout

_crawl_bash() {
    local -n _start_urls=$1
    local out=$2

    for start_url in "${_start_urls[@]}"; do
        [[ "$start_url" =~ ^https?:// ]] || continue
        local base_domain
        base_domain=$(echo "$start_url" | sed -E 's|^https?://([^/:]+).*|\1|')
        local scheme
        scheme=$(echo "$start_url" | grep -oE '^https?')

        log_info "Built-in crawler starting at $start_url (depth=$CRAWL_MAX_DEPTH, max=$CRAWL_MAX_PAGES pages)"

        local visited_file queue_file link_buf
        visited_file=$(mktemp); register_cleanup "$visited_file"
        queue_file=$(mktemp);   register_cleanup "$queue_file"
        link_buf=$(mktemp);     register_cleanup "$link_buf"

        echo "$start_url" > "$queue_file"
        local page_count=0

        while [ -s "$queue_file" ] && [ "$page_count" -lt "$CRAWL_MAX_PAGES" ]; do
            # Pop the first URL from the queue
            local url
            url=$(head -1 "$queue_file")
            sed -i '1d' "$queue_file" 2>/dev/null || { tail -n +2 "$queue_file" > "${queue_file}.t" && mv "${queue_file}.t" "$queue_file"; }

            # Skip already-visited
            grep -qxF "$url" "$visited_file" 2>/dev/null && continue
            echo "$url" >> "$visited_file"

            page_count=$((page_count + 1))
            log_debug "Crawling [$page_count/$CRAWL_MAX_PAGES]: $url"

            # Fetch the page
            local html
            html=$(curl -sk -L \
                --max-time "$CRAWL_TIMEOUT" \
                --max-redirs 3 \
                -A "Mozilla/5.0 (compatible; ExposureScopeX-Crawler/2.1)" \
                "$url" 2>/dev/null) || continue

            # Record this URL
            echo "$url" >> "$out"

            # Extract all href/src/action link targets
            : > "$link_buf"
            echo "$html" | \
                grep -oE '(href|src|action)="[^"#?]*"' | \
                sed -E 's/(href|src|action)="//; s/"//' | \
                grep -Ev '^(mailto:|tel:|javascript:|data:|#|$)' | \
                while IFS= read -r raw_link; do
                    local abs_url=""
                    if [[ "$raw_link" =~ ^https?:// ]]; then
                        # Only follow same-domain absolute links
                        [[ "$raw_link" == *"$base_domain"* ]] && abs_url="$raw_link"
                    elif [[ "$raw_link" =~ ^/ ]]; then
                        abs_url="${scheme}://${base_domain}${raw_link}"
                    elif [[ "$raw_link" =~ ^[a-zA-Z0-9._-] ]]; then
                        # Relative path — append to current page's directory
                        local dir
                        dir=$(echo "$url" | sed 's|[^/]*$||')
                        abs_url="${dir}${raw_link}"
                    fi
                    [ -n "$abs_url" ] && echo "$abs_url"
                done >> "$link_buf"

            # Enqueue newly discovered links
            while IFS= read -r new_url; do
                grep -qxF "$new_url" "$visited_file" 2>/dev/null && continue
                grep -qxF "$new_url" "$queue_file"   2>/dev/null && continue
                echo "$new_url" >> "$queue_file"
            done < "$link_buf"
        done

        log_info "Built-in crawler: $page_count pages crawled on $base_domain"
    done

    # Deduplicate output
    sort -u "$out" -o "$out"
}

# ── Post-processing: extract interesting intel from crawl output ───────────────

_extract_crawler_intel() {
    local crawl_out=$1
    local output_dir=$2

    [ -s "$crawl_out" ] || return 0

    # API endpoints
    grep -iE '/api/|/v[0-9]+/|/graphql|/rest/|/json|/xml' "$crawl_out" 2>/dev/null | \
        sort -u > "${output_dir}/api_endpoints_crawled.txt"

    # JavaScript files
    grep -iE '\.js(\?|$)' "$crawl_out" 2>/dev/null | \
        sort -u > "${output_dir}/js_files_crawled.txt"

    # Login / admin pages
    grep -iE '/(admin|login|portal|dashboard|manage|wp-admin|phpmyadmin|console)' \
        "$crawl_out" 2>/dev/null | sort -u > "${output_dir}/admin_pages_crawled.txt"

    # Interesting file types (potential data leakage)
    grep -iE '\.(pdf|xlsx|docx|csv|sql|bak|zip|tar|gz|env|cfg|conf|log|json|xml)(\?|$)' \
        "$crawl_out" 2>/dev/null | sort -u > "${output_dir}/interesting_files_crawled.txt"

    local api_n js_n admin_n file_n
    api_n=$(wc -l   < "${output_dir}/api_endpoints_crawled.txt"   2>/dev/null || echo 0)
    js_n=$(wc -l    < "${output_dir}/js_files_crawled.txt"        2>/dev/null || echo 0)
    admin_n=$(wc -l < "${output_dir}/admin_pages_crawled.txt"     2>/dev/null || echo 0)
    file_n=$(wc -l  < "${output_dir}/interesting_files_crawled.txt" 2>/dev/null || echo 0)

    log_info "Crawler intel: $api_n API endpoints, $js_n JS files, $admin_n admin pages, $file_n interesting files"
}
