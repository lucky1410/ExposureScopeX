#!/bin/bash

establish_web_auth_session() {
    local output_dir=$1
    [ -n "${EXPOSURESCOPEX_WEB_AUTH_JSON:-}" ] || return 0
    log_info "Establishing operator-approved authenticated web session..."
    EXPOSURESCOPEX_SKIP_POST_TOOL_DELAY=true \
        run_tool "python" "python" /app/worker/web_auth_session.py --output-dir "$output_dir"
}

web_auth_cookie_header() {
    local output_dir=$1
    local cookie_file="${output_dir}/web-auth-cookie.txt"
    [ -s "$cookie_file" ] || return 1
    printf 'Cookie: %s' "$(cat "$cookie_file")"
}
