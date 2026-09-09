#!/bin/bash

# Scope Enforcement Module
# Loads a scope file and filters targets to only in-scope assets
#
# Scope file format (one entry per line, # for comments):
#   example.com           -> exact domain match
#   *.example.com         -> wildcard: all subdomains of example.com
#   192.168.1.0/24        -> IPv4 CIDR range
#   10.0.0.5              -> exact IP
#   # this is a comment   -> ignored

SCOPE_FILE=""
declare -a _SCOPE_DOMAINS=()
declare -a _SCOPE_CIDRS=()
declare -a _SCOPE_IPS=()

# Load scope from file into module-level arrays
load_scope() {
    local scope_file=$1
    if [ ! -f "$scope_file" ]; then
        log_error "Scope file not found: $scope_file"
        return 1
    fi

    SCOPE_FILE="$scope_file"
    _SCOPE_DOMAINS=()
    _SCOPE_CIDRS=()
    _SCOPE_IPS=()

    while IFS= read -r line; do
        # Strip leading/trailing whitespace
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        # Skip blanks and comments
        [[ -z "$line" || "$line" =~ ^# ]] && continue

        if [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
            _SCOPE_CIDRS+=("$line")
        elif validate_ip "$line" 2>/dev/null; then
            _SCOPE_IPS+=("$line")
        else
            _SCOPE_DOMAINS+=("$line")
        fi
    done < "$scope_file"

    log_success "Scope loaded: ${#_SCOPE_DOMAINS[@]} domains, ${#_SCOPE_CIDRS[@]} CIDRs, ${#_SCOPE_IPS[@]} IPs"
    log_info "Scope file: $scope_file"
    return 0
}

# Return 0 if $1 is in scope, 1 if not
is_in_scope() {
    local target=$1

    # No scope file loaded → everything is in scope
    [ -z "$SCOPE_FILE" ] && return 0

    # Domain / subdomain match
    for entry in "${_SCOPE_DOMAINS[@]}"; do
        if [[ "$entry" == \*.* ]]; then
            local base="${entry#\*.}"
            [[ "$target" == "$base" || "$target" == *".$base" ]] && return 0
        else
            [[ "$target" == "$entry" ]] && return 0
        fi
    done

    # Exact IP match
    for ip in "${_SCOPE_IPS[@]}"; do
        [[ "$target" == "$ip" ]] && return 0
    done

    # CIDR match (pure bash, IPv4 only)
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        for cidr in "${_SCOPE_CIDRS[@]}"; do
            _ip_in_cidr "$target" "$cidr" && return 0
        done
    fi

    return 1
}

# Pure-bash IPv4 CIDR containment check
_ip_in_cidr() {
    local ip=$1 cidr=$2
    local net="${cidr%/*}" prefix="${cidr#*/}"
    local ip_int net_int mask_int
    local a b c d

    IFS=. read -r a b c d <<< "$ip"
    ip_int=$(( (a<<24) | (b<<16) | (c<<8) | d ))
    IFS=. read -r a b c d <<< "$net"
    net_int=$(( (a<<24) | (b<<16) | (c<<8) | d ))

    # Bash arithmetic wraps at 32 bits for the mask
    if [ "$prefix" -eq 0 ]; then
        mask_int=0
    else
        mask_int=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    fi

    [ $(( ip_int & mask_int )) -eq $(( net_int & mask_int )) ]
}

# Filter a file of targets, writing only in-scope lines to output file
filter_by_scope() {
    local input_file=$1
    local output_file=$2

    if [ -z "$SCOPE_FILE" ]; then
        cp "$input_file" "$output_file"
        return 0
    fi

    : > "$output_file"
    local total=0 kept=0 excluded=0

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        ((total++)) || true
        if is_in_scope "$line"; then
            echo "$line" >> "$output_file"
            ((kept++)) || true
        else
            log_debug "Out of scope, excluded: $line"
            ((excluded++)) || true
        fi
    done < "$input_file"

    log_info "Scope filter: $total total, $kept in-scope, $excluded excluded"
}

# Check a single target and warn loudly if out of scope
assert_in_scope() {
    local target=$1
    if ! is_in_scope "$target"; then
        log_error "Target '$target' is OUT OF SCOPE — aborting"
        return 1
    fi
    return 0
}

# Print current scope to log
print_scope() {
    if [ -z "$SCOPE_FILE" ]; then
        log_info "No scope file loaded — all targets accepted"
        return
    fi
    log_info "Scope file: $SCOPE_FILE"
    log_info "  Domains (${#_SCOPE_DOMAINS[@]}): ${_SCOPE_DOMAINS[*]}"
    log_info "  CIDRs   (${#_SCOPE_CIDRS[@]}):   ${_SCOPE_CIDRS[*]}"
    log_info "  IPs     (${#_SCOPE_IPS[@]}):     ${_SCOPE_IPS[*]}"
}
