#!/bin/bash

# Cloud Security Module
# Real bucket enumeration (S3/GCS/Azure) + CLI-based misconfiguration checks

run_cloud_scan() {
    local target=$1
    local output_dir=$2
    local cloud_output="${output_dir}/cloud_results.txt"

    log_info "Starting Cloud Security Scan for $target"

    if ! validate_domain "$target"; then
        log_error "Invalid domain for cloud scan: $target"
        return 1
    fi

    : > "$cloud_output"

    # -----------------------------------------------------------------------
    # Nuclei cloud templates
    # -----------------------------------------------------------------------
    if command -v nuclei &>/dev/null; then
        log_info "Running Nuclei cloud templates..."
        run_tool "nuclei" "nuclei" -u "$target" -tags cloud -o "$cloud_output" 2>/dev/null || \
            log_warn "nuclei cloud templates failed (templates may not be installed)"
    fi

    # -----------------------------------------------------------------------
    # Cloud storage bucket enumeration
    # -----------------------------------------------------------------------
    run_bucket_enum "$target" "$output_dir"

    # -----------------------------------------------------------------------
    # Kubernetes API exposure check
    # -----------------------------------------------------------------------
    run_k8s_exposure_check "$target" "$output_dir"

    # -----------------------------------------------------------------------
    # CLI-based authenticated checks (local credentials)
    # -----------------------------------------------------------------------
    {
        echo ""
        echo "=== Authenticated Cloud CLI Checks ==="

        if command -v aws &>/dev/null; then
            echo ""
            echo "--- AWS ---"
            aws sts get-caller-identity 2>&1 && \
                echo "[NOTE] AWS credentials present — run 'prowler' or 'ScoutSuite' for full audit" || \
                echo "[INFO] No AWS credentials configured"
        fi

        if command -v az &>/dev/null; then
            echo ""
            echo "--- Azure ---"
            az account show 2>&1 && \
                echo "[NOTE] Azure credentials present — run 'ScoutSuite' for full audit" || \
                echo "[INFO] No Azure credentials configured"
        fi

        if command -v gcloud &>/dev/null; then
            echo ""
            echo "--- GCP ---"
            gcloud auth list 2>&1 | head -10
            gcloud projects list 2>&1 | head -10 && \
                echo "[NOTE] GCP credentials present — run 'ScoutSuite' or 'Prowler' for full audit" || \
                echo "[INFO] No GCP credentials configured"
        fi

    } >> "$cloud_output"

    log_success "Cloud scan complete: $cloud_output"
    return 0
}

# ---------------------------------------------------------------------------
# Storage bucket enumeration — S3, GCS, Azure Blob
# ---------------------------------------------------------------------------
run_bucket_enum() {
    local domain=$1
    local output_dir=$2
    local bucket_output="${output_dir}/cloud_buckets.txt"

    log_info "Enumerating cloud storage buckets..."
    : > "$bucket_output"

    # Derive company name variants from domain
    local company="${domain%%.*}"
    local domain_dashed="${domain//./-}"

    local -a bucket_names=(
        "$company"
        "$company-backup" "$company-backups"
        "$company-dev" "$company-development" "$company-staging" "$company-stage"
        "$company-prod" "$company-production"
        "$company-data" "$company-assets" "$company-static" "$company-media"
        "$company-public" "$company-private"
        "$company-images" "$company-img"
        "$company-uploads" "$company-files" "$company-docs"
        "$company-logs" "$company-log"
        "$company-config" "$company-secrets"
        "$company-test" "$company-qa"
        "$company-web" "$company-www"
        "$domain_dashed"
        "${company}bucket" "${company}-bucket"
        "${company}store" "${company}-store"
    )

    local found=0

    for bucket in "${bucket_names[@]}"; do
        # --- AWS S3 ---
        local s3_url="https://${bucket}.s3.amazonaws.com"
        local s3_status
        s3_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
            -A "${USER_AGENT:-ExposureScopeX/1.0}" "$s3_url" 2>/dev/null)
        case "$s3_status" in
            200)
                echo "[CRITICAL] S3 PUBLIC READ: $s3_url" | tee -a "$bucket_output"
                # Try to list contents
                local list_resp
                list_resp=$(curl -s --max-time 5 "$s3_url" 2>/dev/null)
                if echo "$list_resp" | grep -q "<Key>"; then
                    echo "           Files are listable!" | tee -a "$bucket_output"
                    echo "$list_resp" | grep -oP '(?<=<Key>)[^<]+' | head -10 | \
                        sed 's/^/           /' | tee -a "$bucket_output"
                fi
                ((found++)) || true
                ;;
            403) echo "[HIGH] S3 EXISTS (private): $s3_url" | tee -a "$bucket_output"; ((found++)) || true ;;
        esac

        # AWS S3 via path-style (us-east-1)
        local s3_path_url="https://s3.amazonaws.com/${bucket}"
        local s3_path_status
        s3_path_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
            -A "${USER_AGENT:-ExposureScopeX/1.0}" "$s3_path_url" 2>/dev/null)
        [ "$s3_path_status" = "200" ] && ! grep -qF "$bucket" "$bucket_output" && \
            echo "[CRITICAL] S3 PUBLIC (path-style): $s3_path_url" | tee -a "$bucket_output"

        # --- Google Cloud Storage ---
        local gcs_url="https://storage.googleapis.com/$bucket"
        local gcs_status
        gcs_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
            -A "${USER_AGENT:-ExposureScopeX/1.0}" "$gcs_url" 2>/dev/null)
        case "$gcs_status" in
            200) echo "[CRITICAL] GCS PUBLIC READ: $gcs_url" | tee -a "$bucket_output"; ((found++)) || true ;;
            403) echo "[HIGH] GCS EXISTS (private): $gcs_url" | tee -a "$bucket_output"; ((found++)) || true ;;
        esac

        # --- Azure Blob Storage ---
        local az_url="https://${company}.blob.core.windows.net/${bucket}"
        local az_status
        az_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
            -A "${USER_AGENT:-ExposureScopeX/1.0}" "$az_url" 2>/dev/null)
        case "$az_status" in
            200|400)
                echo "[HIGH] Azure Blob EXISTS: $az_url (HTTP $az_status)" | tee -a "$bucket_output"
                ((found++)) || true
                ;;
            403) echo "[INFO] Azure Blob EXISTS (private): $az_url" | tee -a "$bucket_output" ;;
        esac

    done

    if [ "$found" -gt 0 ]; then
        log_warn "Cloud bucket enumeration: $found exposure(s) found — see $bucket_output"
    else
        log_success "Cloud bucket enumeration: no public buckets found"
        echo "(No exposed buckets found)" >> "$bucket_output"
    fi
}

# ---------------------------------------------------------------------------
# Kubernetes API server exposure check
# ---------------------------------------------------------------------------
run_k8s_exposure_check() {
    local target=$1
    local output_dir=$2
    local k8s_output="${output_dir}/k8s_exposure.txt"

    log_info "Checking for exposed Kubernetes API servers..."
    : > "$k8s_output"

    # Resolve IPs
    local -a ips=()
    mapfile -t ips < <(dig +short A "$target" 2>/dev/null | grep -E '^[0-9]+\.')
    [ -f "${output_dir}/live_hosts.txt" ] && \
        mapfile -t -O "${#ips[@]}" ips < <(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
            "${output_dir}/live_hosts.txt" 2>/dev/null | sort -u)

    local k8s_found=false
    for ip in "${ips[@]}"; do
        for port in 6443 8080 8443 10250 10255; do
            local resp
            resp=$(curl -sk --max-time 3 "https://${ip}:${port}/version" 2>/dev/null || \
                   curl -s  --max-time 3 "http://${ip}:${port}/version" 2>/dev/null)
            if echo "$resp" | grep -q '"gitVersion"\|"major"'; then
                echo "[CRITICAL] Kubernetes API exposed: ${ip}:${port}" | tee -a "$k8s_output"
                echo "           Response: $(echo "$resp" | head -3)" | tee -a "$k8s_output"
                k8s_found=true
            fi

            # Kubelet read-only port
            if [ "$port" -eq 10255 ]; then
                local pods_resp
                pods_resp=$(curl -s --max-time 3 "http://${ip}:${port}/pods" 2>/dev/null)
                if echo "$pods_resp" | grep -q '"kind":"PodList"'; then
                    echo "[CRITICAL] Kubelet read-only port exposed: ${ip}:${port}/pods" | tee -a "$k8s_output"
                    k8s_found=true
                fi
            fi
        done
    done

    $k8s_found || echo "(No exposed Kubernetes API servers found)" >> "$k8s_output"
    log_success "Kubernetes exposure check complete"
}
