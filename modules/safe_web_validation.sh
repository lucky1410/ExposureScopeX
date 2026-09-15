#!/bin/bash

run_safe_web_validation() {
    local target=$1
    local output_dir=$2
    [ -s "${output_dir}/web-auth-storage-state.json" ] || \
        log_info "No authenticated session configured; baseline coverage is limited to public application pages"
    local -a validation_args=(
        --target "$target" --output-dir "$output_dir" --mode "${MODE:-medium}"
    )
    if [ "${EXPOSURESCOPEX_ACTIVE_VALIDATION:-false}" = "true" ]; then
        validation_args+=(--allow-probes)
        log_info "Running passive baseline plus operator-authorized bounded GET probes..."
    else
        log_info "Running non-mutating passive web security baseline; input probes are disabled"
    fi
    run_tool "python" "python" /app/worker/safe_web_validation.py "${validation_args[@]}"
}
