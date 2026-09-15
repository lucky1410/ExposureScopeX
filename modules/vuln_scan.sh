#!/bin/bash

# Vulnerability Scanning Module

run_vuln_scan() {
    local target=$1
    local output_dir=$2
    local nuclei_output="${output_dir}/nuclei_results.txt"
    local nuclei_targets="${output_dir}/nuclei_targets.txt"
    local nuclei_web_targets="${output_dir}/nuclei_web_targets.txt"
    local templates_dir="${NUCLEI_TEMPLATES_DIR:-${HOME:-/tmp}/nuclei-templates}"
    local extra_templates_root="${NUCLEI_COMMUNITY_TEMPLATES_DIR:-${templates_dir}/external}"
    local extra_template_repos="${NUCLEI_EXTRA_TEMPLATE_REPOS:-${NUCLEI_TEMPLATE_REPOS:-}}"
    local exclude_tags="${NUCLEI_EXCLUDE_TAGS:-dos,fuzz,intrusive}"
    local auto_update_templates="${NUCLEI_AUTO_UPDATE_TEMPLATES:-${NUCLEI_TEMPLATE_AUTOUPDATE:-true}}"
    local refresh_hours="${NUCLEI_TEMPLATE_REFRESH_HOURS:-24}"
    local official_stamp="${templates_dir}/.last-update"
    local community_stamp="${extra_templates_root}/.last-update"
    local -a extra_template_dirs=()
    local -a safety_args=()
    local -a mode_args=()
    [ -n "$exclude_tags" ] && safety_args=(-etags "$exclude_tags")
    local mode_tags="cves,exposures,files,misconfig,tech,takeovers"
    local rate_limit=25 concurrency=10 bulk_size=10 retries=1
    local headless_enabled="${NUCLEI_ENABLE_HEADLESS:-true}"
    case "${MODE:-medium}" in
        light)
            mode_tags="exposures,misconfig"
            rate_limit=10; concurrency=5; bulk_size=5; retries=0; headless_enabled=false
            mode_args=(-severity "critical,high,medium,low" -ni)
            ;;
        aggressive)
            mode_tags="cves,dns,exposures,files,misconfig,panel,takeovers,tech"
            rate_limit=40; concurrency=15; bulk_size=15
            ;;
    esac

    should_refresh_templates() {
        local stamp=$1
        local now_epoch
        local stamp_epoch
        local max_age

        [ "$auto_update_templates" = "true" ] || return 1
        [ -f "$stamp" ] || return 0

        now_epoch=$(date +%s)
        stamp_epoch=$(date -r "$stamp" +%s 2>/dev/null || echo 0)
        max_age=$((refresh_hours * 3600))
        [ $((now_epoch - stamp_epoch)) -ge "$max_age" ]
    }

    register_extra_template_dir() {
        local template_dir=$1
        local repo_name

        [ -d "$template_dir" ] || return 1
        repo_name=$(basename "$template_dir")
        if nuclei -validate -silent -t "$template_dir" > "${output_dir}/nuclei-template-validation-${repo_name}.log" 2>&1; then
            extra_template_dirs+=("$template_dir")
        else
            log_warn "Community template repository failed validation and will not run: $template_dir"
            return 1
        fi
    }

    sync_extra_template_repo() {
        local repo_url=$1
        local repo_name
        local repo_dir

        repo_name=$(basename "${repo_url%.git}")
        repo_name=${repo_name//[^a-zA-Z0-9._-]/_}
        repo_dir="${extra_templates_root}/${repo_name}"
        mkdir -p "$extra_templates_root"

        if [ -d "${repo_dir}/.git" ]; then
            log_info "Updating community nuclei templates: $repo_url"
            git -C "$repo_dir" pull --ff-only >/dev/null 2>&1 || \
                log_warn "Failed to update $repo_url"
        else
            log_info "Cloning community nuclei templates: $repo_url"
            git clone --depth 1 "$repo_url" "$repo_dir" >/dev/null 2>&1 || {
                log_warn "Failed to clone $repo_url"
                return 1
            }
        fi

        register_extra_template_dir "$repo_dir" || return 1
    }

    log_info "Starting Vulnerability Scanning..."

    if ! command -v nuclei &> /dev/null; then
        log_error "nuclei not installed"
        return 1
    fi

    # build target list
    >"$nuclei_targets"
    if [ -f "$target" ]; then
        cat "$target" >> "$nuclei_targets"
    else
        echo "$target" >> "$nuclei_targets"
    fi

    for f in subdomains.txt live_hosts.txt open_ports.txt wayback_urls.txt \
             feroxbuster_results.txt dirsearch_results.txt katana_crawl.txt; do
        if [ -f "${output_dir}/$f" ]; then
            cat "${output_dir}/$f" >> "$nuclei_targets" 2>/dev/null || true
        fi
    done

    local scoped_targets="${nuclei_targets}.scoped"
    filter_targets_to_scope "$target" "$nuclei_targets" "$scoped_targets" || {
        log_error "Nuclei scope containment failed; refusing to scan aggregated targets"
        return 1
    }
    mv "$scoped_targets" "$nuclei_targets"

    # Archive/crawler output can contain millions of URLs. Keep the scan bounded
    # while retaining the primary inventory and a representative URL sample.
    local target_limit="${NUCLEI_TARGET_LIMIT:-2500}"
    local headless_limit="${NUCLEI_HEADLESS_TARGET_LIMIT:-250}"
    [ "${MODE:-medium}" = "light" ] && target_limit="${NUCLEI_TARGET_LIMIT:-75}"
    [ "${MODE:-medium}" = "aggressive" ] && target_limit="${NUCLEI_TARGET_LIMIT:-5000}"
    grep -E -v '^\s*$' "$nuclei_targets" \
        | grep -Eiv '/(logout|logoff|signout|delete|remove|setup|install|reset)([/?#]|$)' \
        | sort -u | head -n "$target_limit" > "${nuclei_targets}.tmp"
    mv "${nuclei_targets}.tmp" "$nuclei_targets"
    local target_count=$(wc -l < "$nuclei_targets" 2>/dev/null || echo 0)
    log_info "Total unique targets for Nuclei: $target_count"

    if [ $target_count -eq 0 ]; then
        log_warn "No targets to scan with nuclei"
        return 0
    fi

    mkdir -p "$templates_dir" 2>/dev/null || true

    # Web workers refresh at startup and through the scheduled maintenance task.
    # Refreshing again inside a bounded scan wastes budget and races shared caches.
    if [ "${AUTO_MODE:-false}" = "true" ]; then
        log_info "Using worker-managed Nuclei template cache"
    elif should_refresh_templates "$official_stamp"; then
        log_info "Refreshing Nuclei templates..."
        if run_tool "nuclei" "nuclei" -update-templates -update-template-dir "$templates_dir"; then
            touch "$official_stamp"
        else
            log_warn "Nuclei template update failed; continuing with existing templates"
        fi
    else
        log_info "Skipping Nuclei template refresh; cached templates are still fresh"
    fi

    if [ "${AUTO_MODE:-false}" = "true" ]; then
        if [ -d "$extra_templates_root" ]; then
            local cached_repo_dir
            for cached_repo_dir in "$extra_templates_root"/*; do
                [ -d "$cached_repo_dir" ] || continue
                register_extra_template_dir "$cached_repo_dir" || true
            done
        fi
    elif [ -n "$extra_template_repos" ]; then
        local old_ifs=$IFS
        local repo_url
        if should_refresh_templates "$community_stamp"; then
            IFS=','
            for repo_url in ${extra_template_repos}; do
                repo_url=$(echo "$repo_url" | xargs)
                [ -n "$repo_url" ] && sync_extra_template_repo "$repo_url"
            done
            IFS=$old_ifs
            touch "$community_stamp"
        else
            log_info "Skipping community Nuclei template refresh; cached repositories are still fresh"
            IFS=','
            for repo_url in ${extra_template_repos}; do
                repo_url=$(echo "$repo_url" | xargs)
                [ -n "$repo_url" ] || continue
                repo_name=$(basename "${repo_url%.git}")
                repo_name=${repo_name//[^a-zA-Z0-9._-]/_}
                register_extra_template_dir "${extra_templates_root}/${repo_name}" || true
            done
            IFS=$old_ifs
        fi
    elif [ -d "$extra_templates_root" ]; then
        local repo_dir
        for repo_dir in "$extra_templates_root"/*; do
            [ -d "$repo_dir" ] || continue
            register_extra_template_dir "$repo_dir" || true
        done
    fi

    : > "$nuclei_output"
    grep -E '^https?://' "$nuclei_targets" | sort -u | head -n "$headless_limit" > "$nuclei_web_targets" 2>/dev/null || true

    local -a base_args=(
        -l "$nuclei_targets"
        -o "$nuclei_output"
        -update-template-dir "$templates_dir"
        -tags "$mode_tags"
        -rl "$rate_limit"
        -c "$concurrency"
        -bs "$bulk_size"
        -stats
        -si 30
        -timeout 10
        -retries "$retries"
        "${safety_args[@]}"
        "${mode_args[@]}"
    )
    if auth_header=$(web_auth_cookie_header "$output_dir" 2>/dev/null); then
        base_args+=(-H "$auth_header")
        log_info "Nuclei is using the operator-approved authenticated session"
    fi

    local template_dir
    for template_dir in "${extra_template_dirs[@]}"; do
        [ -d "$template_dir" ] && base_args+=(-t "$template_dir")
    done

    if [ -n "${NUCLEI_EXTRA_FLAGS:-}" ]; then
        # shellcheck disable=SC2206
        local extra_flags=( ${NUCLEI_EXTRA_FLAGS} )
        base_args+=("${extra_flags[@]}")
    fi

    local primary_pass_failed=false
    if run_tool "nuclei" "nuclei" "${base_args[@]}"; then
        log_success "Nuclei default/community template pass complete"
    else
        log_error "Nuclei default/community template pass failed"
        primary_pass_failed=true
    fi

    if [ "$headless_enabled" = "true" ] && [ -s "$nuclei_web_targets" ]; then
        log_info "Running Nuclei headless templates on web targets..."
        run_tool "nuclei" "nuclei" \
            -headless \
            -l "$nuclei_web_targets" \
            -o "${nuclei_output}.headless" \
            -update-template-dir "$templates_dir" \
            -tags "$mode_tags" \
            "${safety_args[@]}" || \
            log_warn "Nuclei headless template pass failed"
        [ -f "${nuclei_output}.headless" ] && cat "${nuclei_output}.headless" >> "$nuclei_output"
    fi

    if [ "${NUCLEI_ENABLE_CODE_TEMPLATES:-false}" = "true" ]; then
        log_warn "Nuclei code templates are disabled by the non-exploitation platform policy"
    fi

    sort -u "$nuclei_output" -o "$nuclei_output" 2>/dev/null || true

    if [ -s "$nuclei_output" ]; then
        log_success "Nuclei scan complete. Results: $nuclei_output"
    else
        log_warn "Nuclei completed but no findings were written"
    fi
    if [ "$primary_pass_failed" = true ]; then
        return 1
    fi
    return 0
}
