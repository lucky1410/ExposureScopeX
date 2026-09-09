#!/bin/bash

# DNS Reconnaissance Module
# Zone transfers, record enumeration, DNSSEC, ASN, WHOIS

run_dns_recon() {
    local domain=$1
    local output_dir=$2
    local dns_output="${output_dir}/dns_recon.txt"

    if ! validate_domain "$domain"; then
        log_error "Invalid domain for DNS recon: $domain"
        return 1
    fi

    if ! command -v dig &>/dev/null; then
        log_warn "dig not available — skipping DNS recon"
        return 1
    fi

    log_info "Starting DNS Reconnaissance for $domain..."

    {
        echo "=== DNS Reconnaissance: $domain ==="
        echo "Timestamp: $(date)"
        echo ""

        # Core record types
        for rtype in A AAAA NS MX TXT SOA CNAME CAA; do
            echo "--- $rtype Records ---"
            dig +short "$rtype" "$domain" 2>/dev/null || echo "(none)"
            echo ""
        done

        # Zone transfer attempt (AXFR) against every NS
        echo "--- Zone Transfer (AXFR) ---"
        local axfr_success=false
        mapfile -t ns_list < <(dig +short NS "$domain" 2>/dev/null | sed 's/\.$//')
        if [ ${#ns_list[@]} -eq 0 ]; then
            echo "No NS records found"
        else
            for ns in "${ns_list[@]}"; do
                echo "Trying $ns..."
                local axfr_result
                axfr_result=$(dig axfr "$domain" "@$ns" 2>/dev/null)
                if echo "$axfr_result" | grep -qE "Transfer failed|REFUSED|SERVFAIL|communications error" || [ -z "$axfr_result" ]; then
                    echo "  $ns → REFUSED (correctly secured)"
                else
                    echo "  [CRITICAL] $ns → ZONE TRANSFER SUCCEEDED!"
                    echo "$axfr_result"
                    axfr_success=true
                fi
            done
        fi
        echo ""

        # DNSSEC
        echo "--- DNSSEC ---"
        local ds_rec
        ds_rec=$(dig +short DS "$domain" 2>/dev/null)
        if [ -n "$ds_rec" ]; then
            echo "[PRESENT] DS record: $ds_rec"
            if dig +dnssec A "$domain" 2>/dev/null | grep -q "RRSIG"; then
                echo "[OK]      DNSSEC signatures (RRSIG) present and resolving"
            else
                echo "[WARN]    DS record exists but no RRSIG found — DNSSEC may be misconfigured"
            fi
        else
            echo "[MISSING] No DNSSEC — DNS responses are unauthenticated and spoofable"
        fi
        echo ""

        # WHOIS
        echo "--- WHOIS ---"
        if command -v whois &>/dev/null; then
            whois "$domain" 2>/dev/null | grep -E \
                "Registrar:|Registrant|Creation Date:|Updated Date:|Registry Expiry|Expiry Date:|Name Server:|Status:" \
                | head -25
        else
            echo "whois not available"
        fi
        echo ""

        # Primary IP and ASN
        echo "--- IP & ASN ---"
        local primary_ip
        primary_ip=$(dig +short A "$domain" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
        if [ -n "$primary_ip" ]; then
            echo "Primary IP: $primary_ip"

            # Team Cymru ASN lookup
            if command -v whois &>/dev/null; then
                local asn_info
                asn_info=$(whois -h whois.cymru.com " -v $primary_ip" 2>/dev/null | tail -1)
                [ -n "$asn_info" ] && echo "ASN:        $asn_info"
            fi

            # Reverse DNS
            local rdns
            rdns=$(dig +short -x "$primary_ip" 2>/dev/null)
            [ -n "$rdns" ] && echo "Reverse:    $rdns"

            # All A records (CDN detection)
            echo ""
            echo "All A records (CDN/load-balancer detection):"
            dig +short A "$domain" 2>/dev/null | grep -E '^[0-9]+\.' | while read -r ip; do
                local rev
                rev=$(dig +short -x "$ip" 2>/dev/null | head -1)
                echo "  $ip   ${rev:-(no PTR)}"
            done
        else
            echo "(no A records resolved)"
        fi
        echo ""

        # CAA (Certification Authority Authorization)
        echo "--- CAA (Certificate Authority Authorization) ---"
        local caa
        caa=$(dig +short CAA "$domain" 2>/dev/null)
        if [ -n "$caa" ]; then
            echo "[PRESENT] $caa"
        else
            echo "[MISSING] No CAA record — any CA can issue certificates for this domain"
        fi
        echo ""

        # Wildcard DNS check
        echo "--- Wildcard DNS ---"
        local rand_sub="xyzrandomcheck987.$domain"
        local wc_result
        wc_result=$(dig +short A "$rand_sub" 2>/dev/null)
        if [ -n "$wc_result" ]; then
            echo "[FOUND] Wildcard DNS resolves to: $wc_result"
            echo "        Any subdomain will resolve — may inflate enumeration results"
        else
            echo "[OK] No wildcard DNS detected"
        fi
        echo ""

        # dnsrecon (if available)
        if command -v dnsrecon &>/dev/null; then
            echo "--- dnsrecon ---"
            dnsrecon -d "$domain" -t std 2>/dev/null | head -60
            echo ""
        fi

    } > "$dns_output"

    log_success "DNS recon complete: $dns_output"
    return 0
}
