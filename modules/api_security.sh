#!/bin/bash

# API Security Testing Module
# OpenAPI/Swagger discovery, GraphQL, JWT exposure, cloud metadata SSRF

run_api_security() {
    local target=$1
    local output_dir=$2
    local api_output="${output_dir}/api_security.txt"
    local max_base_urls max_api_paths max_gql_paths max_js_urls max_meta_targets max_ssrf_params stage_timeout
    _TOOL_RUN_SEQUENCE=$(( ${_TOOL_RUN_SEQUENCE:-0} + 1 ))
    local module_run_id="api-security-${$}-${_TOOL_RUN_SEQUENCE}"
    local module_started_at
    module_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '%s\t%s\trunning\t\t%s\t\t%s\t%s\n' \
        "$module_run_id" "api-security" "$module_started_at" \
        "run_api_security $target" "api_security.txt" >> "${output_dir}/tool_runs.tsv"

    # API probes multiply quickly across discovered hosts. Keep each profile
    # bounded and record the limit so reduced coverage is never implicit.
    case "${MODE:-medium}" in
        light)
            max_base_urls=3; max_api_paths=10; max_gql_paths=4; max_js_urls=5
            max_meta_targets=1; max_ssrf_params=6; stage_timeout=180
            ;;
        full|aggressive)
            max_base_urls=25; max_api_paths=19; max_gql_paths=7; max_js_urls=30
            max_meta_targets=4; max_ssrf_params=25; stage_timeout=900
            ;;
        *)
            max_base_urls=10; max_api_paths=14; max_gql_paths=5; max_js_urls=10
            max_meta_targets=2; max_ssrf_params=10; stage_timeout=600
            ;;
    esac
    local stage_started=$SECONDS

    log_info "Starting API Security Testing..."
    : > "$api_output"

    # Build URL list from live hosts or target
    local -a base_urls=()
    if [ -f "${output_dir}/live_hosts.txt" ] && [ -s "${output_dir}/live_hosts.txt" ]; then
        mapfile -t base_urls < <(
            awk '{print $1}' "${output_dir}/live_hosts.txt" \
                | grep -E '^https?://' \
                | sed 's#/$##' \
                | sort -u \
                | head -n "$max_base_urls"
        )
    elif validate_domain "$target"; then
        base_urls=("https://$target" "http://$target")
    else
        log_error "No valid targets for API security test"
        printf '%s\t%s\tfailed\t1\t%s\t%s\t%s\t%s\n' \
            "$module_run_id" "api-security" "$module_started_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            "run_api_security $target" "api_security.txt" >> "${output_dir}/tool_runs.tsv"
        return 1
    fi

    local discovered_url_count=${#base_urls[@]}
    local available_url_count=$discovered_url_count
    if [ -f "${output_dir}/live_hosts.txt" ] && [ -s "${output_dir}/live_hosts.txt" ]; then
        available_url_count=$(awk '{print $1}' "${output_dir}/live_hosts.txt" \
            | grep -E '^https?://' | sed 's#/$##' | sort -u | wc -l | tr -d ' ')
    fi
    {
        echo "=== Coverage Policy ==="
        echo "Profile: ${MODE:-medium}"
        echo "Base URLs selected: ${discovered_url_count}/${available_url_count}"
        echo "Stage deadline: ${stage_timeout}s"
        echo "Limits per URL: OpenAPI=${max_api_paths}, GraphQL=${max_gql_paths}, JS=${max_js_urls}, metadata=${max_meta_targets}, SSRF parameters=${max_ssrf_params}"
        [ "$available_url_count" -gt "$discovered_url_count" ] && \
            echo "[COVERAGE LIMIT] $((available_url_count - discovered_url_count)) additional live URL(s) were not tested by this profile."
        echo ""
    } >> "$api_output"

    log_info "API security coverage: ${discovered_url_count}/${available_url_count} live URL(s), deadline ${stage_timeout}s"

    local host_index=0
    local deadline_reached=false
    for base_url in "${base_urls[@]}"; do
        if (( SECONDS - stage_started >= stage_timeout )); then
            deadline_reached=true
            break
        fi
        host_index=$((host_index + 1))
        log_info "API security target ${host_index}/${discovered_url_count}: $base_url"
        {
            echo "=== API Security: $base_url ==="
            echo ""

            # ------------------------------------------------------------------
            # OpenAPI / Swagger discovery
            # ------------------------------------------------------------------
            echo "--- OpenAPI / Swagger Discovery ---"
            local -a api_paths=(
                "/swagger.json" "/swagger.yaml" "/swagger-ui.html"
                "/swagger/v1/swagger.json" "/swagger/v2/swagger.json"
                "/api-docs" "/api-docs.json" "/v1/api-docs" "/v2/api-docs"
                "/openapi.json" "/openapi.yaml" "/openapi/v3/api-docs"
                "/api/swagger.json" "/api/openapi.json"
                "/.well-known/openapi" "/docs" "/redoc"
                "/api/v1/docs" "/api/v2/docs"
            )
            local found_api=false
            for path in "${api_paths[@]:0:$max_api_paths}"; do
                local status
                status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
                    -A "${USER_AGENT:-ExposureScopeX/1.0}" "${base_url}${path}" 2>/dev/null)
                if [[ "$status" == "200" ]]; then
                    echo "[FOUND] ${base_url}${path} (HTTP 200)"
                    found_api=true
                fi
            done
            $found_api || echo "[NOT FOUND] No OpenAPI/Swagger endpoints detected"
            echo ""

            # ------------------------------------------------------------------
            # GraphQL introspection
            # ------------------------------------------------------------------
            echo "--- GraphQL Introspection ---"
            local -a gql_paths=("/graphql" "/api/graphql" "/gql" "/query" "/graphiql" "/playground" "/api/v1/graphql")
            local found_gql=false
            for path in "${gql_paths[@]:0:$max_gql_paths}"; do
                local gql_resp
                gql_resp=$(curl -s -X POST --max-time 5 \
                    -H "Content-Type: application/json" \
                    -A "${USER_AGENT:-ExposureScopeX/1.0}" \
                    -d '{"query":"{__schema{types{name}}}"}' \
                    "${base_url}${path}" 2>/dev/null)
                if echo "$gql_resp" | grep -q '"__schema"'; then
                    echo "[CRITICAL] GraphQL introspection ENABLED at ${base_url}${path}"
                    echo "           Full schema is publicly exposed"
                    found_gql=true
                elif echo "$gql_resp" | grep -q '"data"\|"errors"'; then
                    echo "[FOUND] GraphQL endpoint (introspection disabled) at ${base_url}${path}"
                    found_gql=true
                fi
            done
            $found_gql || echo "[NOT FOUND] No GraphQL endpoints detected"
            echo ""

            # ------------------------------------------------------------------
            # Secrets in JavaScript files
            # ------------------------------------------------------------------
            echo "--- Secrets in JavaScript Files ---"
            local -a js_urls=()
            # Collect JS URLs from crawler output
            for f in katana_crawl.txt wayback_urls.txt feroxbuster_results.txt; do
                [ -f "${output_dir}/$f" ] && \
                        mapfile -t -O "${#js_urls[@]}" js_urls < \
                        <(grep -E "\.js(\?|$)" "${output_dir}/$f" 2>/dev/null | grep "^http" | sort -u | head -n "$max_js_urls")
            done

            if [ ${#js_urls[@]} -eq 0 ]; then
                echo "[INFO] No JavaScript URLs from crawl data to inspect"
            else
                echo "Inspecting ${#js_urls[@]} JS files..."
                local secrets_found=false
                for js_url in "${js_urls[@]}"; do
                    local js_content
                    js_content=$(curl -s --max-time 8 -A "${USER_AGENT:-ExposureScopeX/1.0}" "$js_url" 2>/dev/null)
                    [ -z "$js_content" ] && continue

                    # AWS keys
                    if echo "$js_content" | grep -qE "AKIA[0-9A-Z]{16}"; then
                        echo "[CRITICAL] AWS Access Key ID in: $js_url"
                        secrets_found=true
                    fi
                    # Stripe live key
                    if echo "$js_content" | grep -qE "sk_live_[0-9a-zA-Z]{24,}"; then
                        echo "[CRITICAL] Stripe live secret key in: $js_url"
                        secrets_found=true
                    fi
                    # GitHub tokens
                    if echo "$js_content" | grep -qE "ghp_[a-zA-Z0-9]{36}|github_token\s*=\s*['\"][a-zA-Z0-9]+"; then
                        echo "[HIGH]     GitHub token in: $js_url"
                        secrets_found=true
                    fi
                    # Google API key
                    if echo "$js_content" | grep -qE "AIza[0-9A-Za-z_-]{35}"; then
                        echo "[HIGH]     Google API key in: $js_url"
                        secrets_found=true
                    fi
                    # Generic API key patterns
                    if echo "$js_content" | grep -qiE "(api_key|api_secret|apikey|client_secret)\s*[:=]\s*['\"][a-zA-Z0-9_-]{16,}"; then
                        echo "[MEDIUM]   Possible API credential in: $js_url"
                        secrets_found=true
                    fi
                    # JWT tokens
                    if echo "$js_content" | grep -qE "eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"; then
                        echo "[INFO]     Hardcoded JWT token in: $js_url"
                        secrets_found=true
                    fi
                done
                $secrets_found || echo "[OK] No obvious secrets found in JS files"
            fi
            echo ""

            # ------------------------------------------------------------------
            # Cloud Metadata SSRF probe
            # ------------------------------------------------------------------
            echo "--- Cloud Metadata SSRF Probe ---"
            local -a meta_targets=(
                "http://169.254.169.254/latest/meta-data/"          # AWS
                "http://169.254.169.254/metadata/instance"           # Azure (with header)
                "http://metadata.google.internal/computeMetadata/v1" # GCP
                "http://100.100.100.200/latest/meta-data/"           # Alibaba
            )
            local -a ssrf_params=(
                "url" "redirect" "target" "dest" "destination" "redir"
                "uri" "path" "return" "next" "data" "reference"
                "site" "html" "val" "validate" "domain" "callback"
                "return_url" "continue" "goto" "file" "fetch" "load"
            )

            local ssrf_found=false
            for meta_url in "${meta_targets[@]:0:$max_meta_targets}"; do
                for param in "${ssrf_params[@]:0:$max_ssrf_params}"; do
                    local probe="${base_url}?${param}=${meta_url}"
                    local resp
                    resp=$(curl -s --max-time 3 -A "${USER_AGENT:-ExposureScopeX/1.0}" "$probe" 2>/dev/null)
                    if echo "$resp" | grep -qE "ami-id|instance-id|local-hostname|instance-type|iam|computeMetadata"; then
                        echo "[CRITICAL] SSRF → Cloud metadata via ?${param}=... at $base_url"
                        ssrf_found=true
                        break 2
                    fi
                done
            done
            $ssrf_found || echo "[OK] No obvious SSRF → cloud metadata detected"
            echo ""

            # ------------------------------------------------------------------
            # JWT weakness check (if wayback/crawl URLs have tokens)
            # ------------------------------------------------------------------
            echo "--- JWT in URL Parameters ---"
            local jwt_in_url=false
            for f in wayback_urls.txt katana_crawl.txt; do
                [ -f "${output_dir}/$f" ] && \
                    grep -E "eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+" \
                        "${output_dir}/$f" 2>/dev/null | head -5 | while IFS= read -r line; do
                    echo "[HIGH] JWT token found in URL: $line"
                    jwt_in_url=true
                done
            done
            $jwt_in_url || echo "[OK] No JWT tokens in URL parameters"
            echo ""

        } >> "$api_output"
    done

    if [ "$deadline_reached" = true ]; then
        echo "[COVERAGE LIMIT] Stage deadline reached after ${stage_timeout}s; $((discovered_url_count - host_index)) selected URL(s) were not tested." >> "$api_output"
        log_warn "API security reached its ${stage_timeout}s deadline after ${host_index}/${discovered_url_count} URL(s)"
        printf '%s\t%s\ttimed_out\t124\t%s\t%s\t%s\t%s\n' \
            "$module_run_id" "api-security" "$module_started_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            "run_api_security $target" "api_security.txt" >> "${output_dir}/tool_runs.tsv"
        return 124
    fi

    local module_status="completed"
    [ "$available_url_count" -gt "$discovered_url_count" ] && module_status="warning"
    printf '%s\t%s\t%s\t0\t%s\t%s\t%s\t%s\n' \
        "$module_run_id" "api-security" "$module_status" "$module_started_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "run_api_security $target" "api_security.txt" >> "${output_dir}/tool_runs.tsv"
    log_success "API security testing complete: $api_output"
    return 0
}
