#!/bin/bash

# Integrations Module

send_slack_notification() {
    local message=$1
    local file_path=$2
    
    if [ "$SLACK_NOTIFY" != true ] || [ -z "$SLACK_WEBHOOK_URL" ]; then
        return 0
    fi

    log_info "Sending Slack Notification..."
    
    # Send text
    curl -s -X POST -H 'Content-type: application/json' --data "{\"text\":\"$message\"}" "$SLACK_WEBHOOK_URL"
    
    # Upload file if provided (requires Slack API Token, not just webhook, usually. 
    # Webhooks don't support file upload easily. 
    # For this implementation, we'll just send text summary via webhook.)
    if [ -n "$file_path" ]; then
         curl -s -X POST -H 'Content-type: application/json' --data "{\"text\":\"Report generated: $file_path\"}" "$SLACK_WEBHOOK_URL"
    fi
}

send_teams_notification() {
    local message=$1
    
    if [ "$TEAMS_NOTIFY" != true ] || [ -z "$TEAMS_WEBHOOK_URL" ]; then
        return 0
    fi

    log_info "Sending Teams Notification..."
    curl -s -X POST -H 'Content-Type: application/json' -d "{\"text\": \"$message\"}" "$TEAMS_WEBHOOK_URL"
}

send_siem_log() {
    local log_entry=$1
    
    if [ "$SIEM_NOTIFY" != true ]; then
        return 0
    fi

    log_info "Sending to SIEM..."
    
    # Splunk HEC Example
    if [ -n "$SPLUNK_HEC_URL" ] && [ -n "$SPLUNK_HEC_TOKEN" ]; then
        curl -s -k "$SPLUNK_HEC_URL" \
            -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
            -d "{\"event\": \"$log_entry\"}"
    fi
    
    # Syslog/Netcat fallback (local syslog)
    logger -t ExposureScopeX "$log_entry"
}
