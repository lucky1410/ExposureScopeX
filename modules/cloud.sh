#!/bin/bash

# Cloud Misconfiguration Module

run_cloud_scan() {
    local target=$1
    local output_dir=$2
    local cloud_output="${output_dir}/cloud_results.txt"

    log_info "Starting Cloud Misconfiguration Scan..."

    # 1. Nuclei Cloud Templates
    if command -v nuclei &> /dev/null; then
        log_info "Running Nuclei Cloud Templates..."
        nuclei -u "$target" -t cloud/ -o "$cloud_output"
    fi

    # 2. AWS CLI
    if command -v aws &> /dev/null; then
        log_info "Checking AWS Identity..."
        aws sts get-caller-identity >> "$cloud_output" 2>&1
        # Add more checks if desired, e.g. s3 ls
    fi

    # 3. Azure CLI
    if command -v az &> /dev/null; then
        log_info "Checking Azure Identity..."
        az account show >> "$cloud_output" 2>&1
    fi

    # 4. GCP CLI
    if command -v gcloud &> /dev/null; then
        log_info "Checking GCP Info..."
        gcloud info >> "$cloud_output" 2>&1
    fi
}
