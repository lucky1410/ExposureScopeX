#!/bin/bash

## Safe execution helpers
# Execute a command safely with proper argument handling
safe_execute() {
    local cmd=$1
    shift || true
    local args=("$@")

    if [ -z "$cmd" ]; then
        log_error "safe_execute: No command specified"
        return 1
    fi

    if ! command -v "$cmd" &> /dev/null; then
        log_error "Command not found: $cmd"
        return 127
    fi

    "$cmd" "${args[@]}"
    return $?
}

# Execute tool with timeout (uses coreutils timeout if available)
execute_with_timeout() {
    local timeout_sec=$1
    local tool=$2
    shift 2 || true
    local args=("$@")

    if command -v timeout &> /dev/null; then
        timeout "$timeout_sec" "$tool" "${args[@]}"
        return $?
    else
        # Fallback: run without timeout
        "$tool" "${args[@]}"
        return $?
    fi
}
