#!/bin/bash

# Reporting Module

generate_report() {
    local session_dir=$1
    local report_md="${session_dir}/report.md"
    local report_pdf="${session_dir}/report.pdf"

    log_info "Generating Report..."

    {
        echo "# ExposureScopeX Report"
        echo "Date: $(date)"
        echo "Target Directory: $session_dir"
        echo ""
        echo "## Summary"
        echo "Automated scan conducted by ExposureScopeX Framework."
        echo ""
        
        echo "## Findings"
        
        if [ -f "${session_dir}/subdomains.txt" ]; then
            echo "### Subdomains"
            echo "\`\`\`"
            cat "${session_dir}/subdomains.txt"
            echo "\`\`\`"
        fi

        if [ -f "${session_dir}/nmap_scan.txt" ]; then
            echo "### Port Scan (Nmap)"
            echo "\`\`\`"
            cat "${session_dir}/nmap_scan.txt"
            echo "\`\`\`"
        fi

        if [ -f "${session_dir}/nuclei_results.txt" ]; then
            echo "### Vulnerabilities (Nuclei)"
            # Parse Nuclei results and apply colors
            while IFS= read -r line; do
                if [[ "$line" == *"[critical]"* ]]; then
                    echo "<div class='severity-critical'>$line</div>"
                elif [[ "$line" == *"[high]"* ]]; then
                    echo "<div class='severity-high'>$line</div>"
                elif [[ "$line" == *"[medium]"* ]]; then
                    echo "<div class='severity-medium'>$line</div>"
                elif [[ "$line" == *"[low]"* ]]; then
                    echo "<div class='severity-low'>$line</div>"
                elif [[ "$line" == *"[info]"* ]]; then
                    echo "<div class='severity-info'>$line</div>"
                else
                    echo "<div class='severity-unknown'>$line</div>"
                fi
            done < "${session_dir}/nuclei_results.txt"
        fi

        if [ -f "${session_dir}/osint_results.txt" ]; then
            echo "### OSINT Findings"
            echo "\`\`\`"
            cat "${session_dir}/osint_results.txt"
            echo "\`\`\`"
        fi

        echo "## Recommendations"
        echo "1. Review all critical vulnerabilities immediately."
        echo "2. Close unused ports."
        echo "3. Rotate exposed credentials."

    } > "$report_md"

    log_success "Markdown report generated: $report_md"

    # Check for Pandoc and PDF Engine
    local css_file="${CONFIG_DIR}/report.css"
    local pandoc_opts=""
    
    if [ -f "$css_file" ]; then
        pandoc_opts="--css $css_file"
    fi

    if check_dependency "pandoc"; then
        if check_dependency "weasyprint"; then
            log_info "Converting to PDF using WeasyPrint..."
            pandoc "$report_md" -o "$report_pdf" --pdf-engine=weasyprint $pandoc_opts
            log_success "PDF report generated: $report_pdf"
        elif check_dependency "wkhtmltopdf"; then
             log_info "Converting to PDF using wkhtmltopdf..."
             pandoc "$report_md" -o "$report_pdf" --pdf-engine=wkhtmltopdf $pandoc_opts
             log_success "PDF report generated: $report_pdf"
        elif check_dependency "pdflatex"; then
             log_info "Converting to PDF using pdflatex..."
             pandoc "$report_md" -o "$report_pdf" --pdf-engine=pdflatex
             log_success "PDF report generated: $report_pdf"
        else
            log_warn "No suitable PDF engine found (weasyprint, wkhtmltopdf, pdflatex). Skipping PDF generation."
        fi
    else
        log_warn "Pandoc missing. Skipping PDF generation."
    fi
}
