#!/bin/bash

# SSL/TLS, HTTP Security Headers, and Email Security Module

run_ssl_check() {
    local target=$1
    local output_dir=$2
    local ssl_output="${output_dir}/ssl_results.txt"
    local headers_output="${output_dir}/http_headers.txt"

    log_info "Starting SSL/TLS and HTTP Security Header checks..."

    : > "$ssl_output"
    : > "$headers_output"

    # Build list of URLs to check
    local -a check_targets=()
    if [ -f "${output_dir}/live_hosts.txt" ] && [ -s "${output_dir}/live_hosts.txt" ]; then
        mapfile -t check_targets < "${output_dir}/live_hosts.txt"
    elif validate_domain "$target"; then
        check_targets=("https://$target" "http://$target")
    else
        log_warn "No valid targets for SSL check"
        return 1
    fi

    # -----------------------------------------------------------------------
    # SSL/TLS Analysis
    # -----------------------------------------------------------------------
    if command -v testssl.sh &>/dev/null || command -v testssl &>/dev/null; then
        local testssl_bin
        testssl_bin=$(command -v testssl.sh 2>/dev/null || command -v testssl 2>/dev/null)
        log_info "Running testssl.sh..."
        for t in "${check_targets[@]}"; do
            [[ "$t" != https://* ]] && continue
            local host
            host=$(echo "$t" | sed 's|https://||' | cut -d/ -f1)
            local json_out="${output_dir}/testssl_$(echo "$host" | md5sum | cut -d' ' -f1).json"
            run_tool "testssl.sh" "testssl" \
                --quiet --severity MEDIUM --jsonfile "$json_out" "$host" \
                >> "$ssl_output" 2>&1 || log_warn "testssl failed on $host"
        done
    else
        log_info "testssl.sh not found — running basic OpenSSL checks..."
        for t in "${check_targets[@]}"; do
            [[ "$t" != https://* ]] && continue
            local host
            host=$(echo "$t" | sed 's|https://||' | cut -d/ -f1 | cut -d: -f1)
            {
                echo "=== SSL Check: $host ==="
                echo ""

                # Certificate info
                echo "--- Certificate ---"
                local cert_info
                cert_info=$(echo | openssl s_client -connect "${host}:443" \
                    -servername "$host" 2>/dev/null | openssl x509 -noout \
                    -subject -issuer -dates -fingerprint 2>/dev/null)
                if [ -z "$cert_info" ]; then
                    echo "Could not retrieve certificate"
                else
                    echo "$cert_info"

                    # Days until expiry
                    local expiry
                    expiry=$(echo | openssl s_client -connect "${host}:443" \
                        -servername "$host" 2>/dev/null | \
                        openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
                    if [ -n "$expiry" ]; then
                        local exp_epoch now_epoch days_left
                        exp_epoch=$(date -d "$expiry" +%s 2>/dev/null || \
                            date -j -f "%b %d %T %Y %Z" "$expiry" +%s 2>/dev/null || echo "")
                        now_epoch=$(date +%s)
                        if [ -n "$exp_epoch" ] && [ "$exp_epoch" -gt 0 ]; then
                            days_left=$(( (exp_epoch - now_epoch) / 86400 ))
                            if   [ "$days_left" -lt 0 ];  then echo "[CRITICAL] Certificate EXPIRED $((days_left * -1)) days ago!"
                            elif [ "$days_left" -lt 14 ]; then echo "[CRITICAL] Certificate expires in $days_left days!"
                            elif [ "$days_left" -lt 30 ]; then echo "[HIGH]     Certificate expires in $days_left days"
                            elif [ "$days_left" -lt 90 ]; then echo "[MEDIUM]   Certificate expires in $days_left days"
                            else                               echo "[OK]       Certificate valid for $days_left more days"
                            fi
                        fi
                    fi
                fi
                echo ""

                # Protocol support
                echo "--- Protocol Support ---"
                for proto in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
                    if echo | openssl s_client -connect "${host}:443" \
                        -"${proto//_/.}" 2>&1 | grep -q "CONNECTED" 2>/dev/null; then
                        case "$proto" in
                            ssl2|ssl3|tls1|tls1_1)
                                echo "[WEAK]   $proto is supported — should be disabled" ;;
                            *)
                                echo "[OK]     $proto is supported" ;;
                        esac
                    fi
                done
                echo ""

                # Cipher strength check (look for weak ciphers)
                echo "--- Cipher Check ---"
                local cipher
                cipher=$(echo | openssl s_client -connect "${host}:443" \
                    -servername "$host" 2>/dev/null | grep "Cipher    :")
                echo "$cipher"
                echo ""

            } >> "$ssl_output"
        done
    fi

    # -----------------------------------------------------------------------
    # HTTP Security Headers
    # -----------------------------------------------------------------------
    log_info "Checking HTTP Security Headers..."

    for t in "${check_targets[@]}"; do
        {
            echo "=== Security Headers: $t ==="
            echo ""
            local headers
            headers=$(curl -s -I -L --max-time 10 -A "${USER_AGENT:-ExposureScopeX/1.0}" "$t" 2>/dev/null)

            if [ -z "$headers" ]; then
                echo "  Could not retrieve headers"
                echo ""
                continue
            fi

            local issues=0
            _check_header() {
                local name=$1 rec=$2
                if echo "$headers" | grep -qi "^${name}:"; then
                    echo "  [OK]      $name: $(echo "$headers" | grep -i "^${name}:" | head -1 | cut -d: -f2- | xargs)"
                else
                    echo "  [MISSING] $name — $rec"
                    ((issues++)) || true
                fi
            }

            echo "Security Header Analysis:"
            _check_header "Strict-Transport-Security"  "Recommended: max-age=31536000; includeSubDomains; preload"
            _check_header "Content-Security-Policy"    "Define allowed content sources to prevent XSS"
            _check_header "X-Frame-Options"            "Recommended: DENY or SAMEORIGIN (clickjacking protection)"
            _check_header "X-Content-Type-Options"     "Recommended: nosniff"
            _check_header "Referrer-Policy"            "Recommended: strict-origin-when-cross-origin"
            _check_header "Permissions-Policy"         "Restrict browser APIs (camera, microphone, geolocation)"
            _check_header "X-XSS-Protection"           "Recommended: 1; mode=block (legacy browsers)"
            echo ""

            echo "Information Disclosure:"
            local server_hdr
            server_hdr=$(echo "$headers" | grep -i "^Server:" | head -1)
            [ -n "$server_hdr" ] && echo "  [DISCLOSURE] $server_hdr"

            local powered_hdr
            powered_hdr=$(echo "$headers" | grep -i "^X-Powered-By:" | head -1)
            [ -n "$powered_hdr" ] && echo "  [DISCLOSURE] $powered_hdr"

            local aspnet_hdr
            aspnet_hdr=$(echo "$headers" | grep -i "^X-AspNet-Version:" | head -1)
            [ -n "$aspnet_hdr" ] && echo "  [DISCLOSURE] $aspnet_hdr"

            echo ""
            echo "CORS:"
            local cors
            cors=$(echo "$headers" | grep -i "Access-Control-Allow-Origin:" | head -1)
            if echo "$cors" | grep -q "\*"; then
                echo "  [MISCONFIGURATION] Wildcard CORS — $cors"
            elif [ -n "$cors" ]; then
                echo "  [INFO] $cors"
            else
                echo "  [OK] No wildcard CORS"
            fi

            echo ""
            echo "Missing security headers: $issues / 7"
            echo ""

        } >> "$headers_output"
    done

    log_success "SSL/TLS check: $ssl_output"
    log_success "HTTP headers:  $headers_output"
    return 0
}

# ---------------------------------------------------------------------------
# Email Security Checks — SPF, DKIM, DMARC
# ---------------------------------------------------------------------------
run_email_security_check() {
    local domain=$1
    local output_dir=$2
    local email_output="${output_dir}/email_security.txt"

    if ! command -v dig &>/dev/null; then
        log_warn "dig not found — skipping email security check"
        return 1
    fi

    log_info "Checking email security records for $domain..."

    {
        echo "=== Email Security: $domain ==="
        echo "Timestamp: $(date)"
        echo ""

        # SPF
        echo "--- SPF ---"
        local spf
        spf=$(dig +short TXT "$domain" 2>/dev/null | grep -i "v=spf1" | tr -d '"')
        if [ -n "$spf" ]; then
            echo "[PRESENT] $spf"
            if   echo "$spf" | grep -q "+all";  then echo "[CRITICAL] +all allows any server to send — completely ineffective"
            elif echo "$spf" | grep -q "?all";  then echo "[HIGH]     ?all is neutral — same as no enforcement"
            elif echo "$spf" | grep -q "~all";  then echo "[MEDIUM]   ~all softfail — consider upgrading to -all"
            elif echo "$spf" | grep -q "\-all"; then echo "[OK]       -all hardfail — correct enforcement"
            fi
        else
            echo "[CRITICAL] No SPF record — domain can be spoofed freely"
        fi
        echo ""

        # DMARC
        echo "--- DMARC ---"
        local dmarc
        dmarc=$(dig +short TXT "_dmarc.$domain" 2>/dev/null | tr -d '"')
        if [ -n "$dmarc" ]; then
            echo "[PRESENT] $dmarc"
            if   echo "$dmarc" | grep -q "p=none";       then echo "[HIGH]   p=none — monitoring only, no enforcement, phishing still possible"
            elif echo "$dmarc" | grep -q "p=quarantine"; then echo "[MEDIUM] p=quarantine — messages go to spam"
            elif echo "$dmarc" | grep -q "p=reject";     then echo "[OK]     p=reject — full enforcement"
            fi
            # Check for RUA (aggregate reporting)
            if ! echo "$dmarc" | grep -q "rua="; then
                echo "[MEDIUM] No rua= tag — aggregate failure reports disabled"
            fi
        else
            echo "[HIGH] No DMARC record — phishing risk not mitigated"
        fi
        echo ""

        # DKIM (probe common selectors)
        echo "--- DKIM (Common Selectors) ---"
        local dkim_found=false
        for sel in default google mail dkim selector1 selector2 k1 s1 s2 mailchimp sendgrid; do
            local dkim
            dkim=$(dig +short TXT "${sel}._domainkey.${domain}" 2>/dev/null | tr -d '"')
            if [ -n "$dkim" ]; then
                echo "[PRESENT] selector=$sel  ${dkim:0:80}..."
                dkim_found=true
                # Check key length
                if echo "$dkim" | grep -q "p="; then
                    local key_len
                    key_len=$(echo "$dkim" | grep -oP 'p=\K[A-Za-z0-9+/=]+' | tr -d '\n' | wc -c)
                    [ "$key_len" -lt 200 ] && echo "[MEDIUM]  Key may be shorter than 2048-bit — consider rotating"
                fi
            fi
        done
        $dkim_found || echo "[INFO] No DKIM records found for common selectors"
        echo ""

        # MX
        echo "--- MX Records ---"
        dig +short MX "$domain" 2>/dev/null | sort -n | while read -r priority mx; do
            echo "  Priority $priority: $mx"
        done
        echo ""

        # MTA-STS (modern email auth)
        echo "--- MTA-STS ---"
        local mta_sts
        mta_sts=$(dig +short TXT "_mta-sts.$domain" 2>/dev/null | tr -d '"')
        if [ -n "$mta_sts" ]; then
            echo "[PRESENT] $mta_sts"
        else
            echo "[INFO] No MTA-STS record — email transit encryption not enforced"
        fi
        echo ""

    } > "$email_output"

    log_success "Email security check: $email_output"
    return 0
}
