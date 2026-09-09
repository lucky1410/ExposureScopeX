#!/bin/bash

# Centralized cleanup and signal handling
# Tracks files that should be removed when the script exits
declare -a CLEANUP_FILES=()

register_cleanup() {
    local file=$1
    if [ -n "$file" ]; then
        CLEANUP_FILES+=("$file")
    fi
}

setup_signal_handlers() {
    trap cleanup_on_exit EXIT
    trap handle_interrupt SIGINT SIGTERM
}

cleanup_on_exit() {
    local exit_code=$?
    log_info "Performing cleanup..."

    # Remove any registered temporary files
    for f in "${CLEANUP_FILES[@]}"; do
        rm -f "$f" 2>/dev/null || true
    done

    # Attempt to kill background jobs (best-effort)
    if jobs -p &> /dev/null; then
        jobs -p | xargs -r kill 2>/dev/null || true
    fi

    if [ $exit_code -eq 0 ]; then
        log_success "Session completed successfully"
    else
        log_error "Session terminated with exit code $exit_code"
    fi
    return $exit_code
}

# Global counter for consecutive interrupts
INTERRUPT_COUNT=0
SKIP_THIS_TOOL=false


handle_interrupt() {
    # increment interrupt counter
    ((INTERRUPT_COUNT++))

    # on second rapid interrupt (before tool completion), force exit
    if [ "$INTERRUPT_COUNT" -gt 1 ]; then
        echo
        log_warn "Second interrupt detected. Forcing exit."
        exit 130
    fi

    # first interrupt: show prompt
    echo
    log_warn "Interrupt received. (s)kip current tool, (q)uit entire session, or press ENTER to continue?"
    read -r -n1 choice
    echo
    case "$choice" in
        s|S)
            log_info "User requested to skip current tool"
            SKIP_THIS_TOOL=true
            INTERRUPT_COUNT=0  # reset for next tool
            return 0
            ;;
        q|Q)
            log_warn "User requested quit. Exiting..."
            exit 130
            ;;
        *)
            log_info "Continuing current operation"
            INTERRUPT_COUNT=0  # reset counter
            return 0
            ;;
    esac
}
