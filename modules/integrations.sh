#!/bin/bash

# Integrations Module
# Slack, Microsoft Teams, SIEM (Splunk HEC + syslog)
# All JSON payloads are built with jq to prevent injection via special characters.

send_slack_notification() {
    local message=$1
    local file_path=${2:-}

    if [ "$SLACK_NOTIFY" != true ] || [ -z "$SLACK_WEBHOOK_URL" ]; then
        return 0
    fi

    if ! command -v jq &>/dev/null; then
        log_warn "jq required for Slack notifications — skipping"
        return 1
    fi

    log_info "Sending Slack notification"

    local payload
    payload=$(jq -n \
        --arg text "$message" \
        --arg report "$file_path" \
        '{
            text: $text,
            attachments: [{
                color: "#36a64f",
                text: ("Report: " + $report)
            }]
        }')

    local resp
    resp=$(curl -s -X POST \
        -H 'Content-type: application/json' \
        --data "$payload" \
        "$SLACK_WEBHOOK_URL" 2>/dev/null)

    if ! echo "$resp" | grep -q '"ok"'; then
        log_error "Slack webhook returned error: $resp"
        return 1
    fi
    return 0
}

send_teams_notification() {
    local message=$1
    local severity=${2:-info}

    if [ "$TEAMS_NOTIFY" != true ] || [ -z "$TEAMS_WEBHOOK_URL" ]; then
        return 0
    fi

    if ! command -v jq &>/dev/null; then
        log_warn "jq required for Teams notifications — skipping"
        return 1
    fi

    log_info "Sending Teams notification"

    local color="0078D4"
    case "$severity" in
        critical) color="C50F1F" ;;
        error)    color="E81B23" ;;
        warning)  color="FFB900" ;;
        info)     color="0078D4" ;;
    esac

    local payload
    payload=$(jq -n \
        --arg color "$color" \
        --arg text  "$message" \
        '{
            "@type":    "MessageCard",
            "@context": "https://schema.org/extensions",
            themeColor: $color,
            text:       $text
        }')

    if ! curl -s -X POST \
        -H 'Content-Type: application/json' \
        --data "$payload" \
        "$TEAMS_WEBHOOK_URL" &>/dev/null; then
        log_error "Teams webhook request failed"
        return 1
    fi
    return 0
}

send_siem_log() {
    local log_entry=$1
    local severity=${2:-INFO}

    if [ "$SIEM_NOTIFY" != true ]; then
        return 0
    fi

    log_info "Logging to SIEM"

    # Splunk HTTP Event Collector
    if [ -n "$SPLUNK_HEC_URL" ] && [ -n "$SPLUNK_HEC_TOKEN" ]; then
        case "$SPLUNK_HEC_URL" in
            https://*) ;;
            *)
                log_warn "Splunk HEC URL must use HTTPS — skipping"
                return 1
                ;;
        esac
        if ! command -v jq &>/dev/null; then
            log_warn "jq required for Splunk HEC — skipping"
        else
            local payload
            payload=$(jq -n \
                --arg event    "$log_entry" \
                --arg severity "$severity" \
                '{ event: $event, severity: $severity }')

            curl --silent --show-error --fail "$SPLUNK_HEC_URL" \
                -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
                -H "Content-Type: application/json" \
                --data "$payload" &>/dev/null || \
                log_warn "Failed to send to Splunk HEC"
        fi
    fi

    # System syslog fallback
    if command -v logger &>/dev/null; then
        logger -t ExposureScopeX -p "security.${severity,,}" "$log_entry" 2>/dev/null || true
    fi
}
