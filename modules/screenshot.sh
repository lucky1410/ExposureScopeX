#!/bin/bash

# Screenshot Module
# Captures visual snapshots of live web targets.
# Tool priority: gowitness → eyewitness → HTML URL index (built-in fallback)

run_screenshots() {
    local target=$1
    local output_dir=$2
    local screenshot_dir="${output_dir}/screenshots"
    mkdir -p "$screenshot_dir"

    # ── Build a URL list from available upstream outputs ──────────────────
    local urls_file=""
    for candidate in \
        "${output_dir}/live_hosts.txt" \
        "${output_dir}/katana_crawl.txt" \
        "${output_dir}/crawl_results.txt"; do
        if [ -s "$candidate" ]; then
            urls_file="$candidate"
            break
        fi
    done

    # No upstream list: construct from the target itself
    if [ -z "$urls_file" ]; then
        local ttype
        ttype=$(detect_target_type "$target" 2>/dev/null)
        local tmp_urls
        tmp_urls=$(mktemp)
        register_cleanup "$tmp_urls"
        case "$ttype" in
            url)    echo "$target" > "$tmp_urls" ;;
            domain|ip) printf 'http://%s\nhttps://%s\n' "$target" "$target" > "$tmp_urls" ;;
            *)
                log_warn "Screenshots: no URL list and target type '$ttype' is not web-compatible"
                return 0
                ;;
        esac
        urls_file="$tmp_urls"
    fi

    local count
    count=$(grep -c . "$urls_file" 2>/dev/null || echo 0)
    log_info "Capturing screenshots for $count URL(s)..."

    # ── Tool selection ─────────────────────────────────────────────────────
    if command -v gowitness &>/dev/null; then
        log_info "Using gowitness..."
        run_tool "gowitness" "gowitness" scan file \
            --file "$urls_file" \
            --screenshot-path "$screenshot_dir" \
            --disable-db 2>/dev/null || log_warn "gowitness encountered errors"

    elif command -v eyewitness &>/dev/null; then
        log_info "Using EyeWitness..."
        run_tool "eyewitness" "eyewitness" --web \
            -f "$urls_file" \
            -d "$screenshot_dir" \
            --no-prompt 2>/dev/null || log_warn "eyewitness encountered errors"

    else
        log_warn "No screenshot tool found — generating HTML URL index instead"
        log_warn "Install gowitness: go install github.com/sensepost/gowitness/v3@latest"
        _generate_url_index "$urls_file" "$screenshot_dir"
        return 0
    fi

    # ── HTML gallery ───────────────────────────────────────────────────────
    _generate_screenshot_gallery "$screenshot_dir" "$urls_file"
    log_success "Screenshots saved: $screenshot_dir/index.html"
}

# Built-in fallback: a dark-themed HTML page of clickable links
_generate_url_index() {
    local urls_file=$1
    local out_dir=$2
    local index="${out_dir}/url_index.html"

    {
        cat <<'HTML'
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>URL Index — ExposureScopeX</title>
<style>
  body{font-family:monospace;background:#1e1e1e;color:#ccc;padding:24px;margin:0}
  h2{color:#4ec9b0;margin-bottom:16px}
  .url-list{display:flex;flex-direction:column;gap:4px}
  a{color:#9cdcfe;padding:4px 8px;border-radius:3px;text-decoration:none;font-size:13px}
  a:hover{background:#2d2d30;color:#4ec9b0}
  .count{color:#888;font-size:12px;margin-bottom:12px}
</style></head><body>
<h2>ExposureScopeX — Discovered URLs</h2>
HTML
        local n
        n=$(grep -c . "$urls_file" 2>/dev/null || echo 0)
        echo "<p class='count'>$n URLs found — $(date)</p>"
        echo "<div class='url-list'>"
        while IFS= read -r url; do
            [[ "$url" =~ ^https?:// ]] || continue
            local escaped
            escaped=$(echo "$url" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
            echo "  <a href='$escaped' target='_blank' rel='noopener'>$escaped</a>"
        done < "$urls_file"
        echo "</div></body></html>"
    } > "$index"

    log_info "URL index generated: $index"
}

# HTML gallery page linking to captured screenshots
_generate_screenshot_gallery() {
    local shot_dir=$1
    local urls_file=$2
    local index="${shot_dir}/index.html"

    # Collect image files
    local -a imgs=()
    for ext in png jpg jpeg; do
        while IFS= read -r -d '' f; do
            imgs+=("$f")
        done < <(find "$shot_dir" -maxdepth 1 -name "*.${ext}" -print0 2>/dev/null)
    done

    if [ ${#imgs[@]} -eq 0 ]; then
        _generate_url_index "$urls_file" "$shot_dir"
        return
    fi

    {
        cat <<'HTML'
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Screenshot Gallery — ExposureScopeX</title>
<style>
  body{font-family:sans-serif;background:#1e1e1e;color:#ccc;padding:20px;margin:0}
  h2{color:#4ec9b0}
  .meta{color:#888;font-size:12px;margin-bottom:20px}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px}
  .card{background:#2d2d30;border-radius:6px;overflow:hidden;border:1px solid #3e3e42}
  .card img{width:100%;height:220px;object-fit:cover;display:block}
  .card p{font-size:11px;word-break:break-all;margin:0;padding:8px;color:#9cdcfe}
  .card a{text-decoration:none}
</style></head><body>
<h2>ExposureScopeX — Screenshot Gallery</h2>
HTML
        echo "<p class='meta'>${#imgs[@]} screenshots — $(date)</p>"
        echo "<div class='grid'>"
        for img in "${imgs[@]}"; do
            local fname
            fname=$(basename "$img")
            echo "  <div class='card'>"
            echo "    <a href='$fname' target='_blank'><img src='$fname' loading='lazy' alt='$fname'></a>"
            echo "    <p>$fname</p>"
            echo "  </div>"
        done
        echo "</div></body></html>"
    } > "$index"

    log_info "Screenshot gallery: $index (${#imgs[@]} images)"
}
