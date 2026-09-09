#!/bin/bash

# Findings Database Module
# Persists findings to SQLite for cross-scan deduplication, querying,
# and remediation tracking.  Falls back to a TSV flat-file when sqlite3
# is unavailable.
#
# Schema (SQLite):
#   scans    (id, target, timestamp, session_dir, mode)
#   findings (id, scan_id, target, severity, category, title, description,
#             url, status, first_seen, last_seen)
#
# Statuses: new | known | suppressed | remediated | false_positive

DB_FILE="${RESULTS_DIR:-results}/findings.db"
TSV_FILE="${RESULTS_DIR:-results}/findings.tsv"

# ── Init ──────────────────────────────────────────────────────────────────────

db_init() {
    DB_FILE="${RESULTS_DIR}/findings.db"
    TSV_FILE="${RESULTS_DIR}/findings.tsv"

    if command -v sqlite3 &>/dev/null; then
        sqlite3 "$DB_FILE" <<'SQL'
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT    NOT NULL,
    timestamp   TEXT    NOT NULL,
    session_dir TEXT,
    mode        TEXT DEFAULT 'medium'
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER REFERENCES scans(id),
    target      TEXT NOT NULL,
    severity    TEXT NOT NULL,  -- CRITICAL HIGH MEDIUM LOW INFO
    category    TEXT NOT NULL,  -- vuln ssl port api cloud osint
    title       TEXT NOT NULL,
    description TEXT,
    url         TEXT,
    status      TEXT DEFAULT 'new',  -- new known suppressed remediated false_positive
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS findings_dedup
    ON findings(target, category, title);
SQL
        log_info "Findings database: $DB_FILE"
    else
        log_warn "sqlite3 not found — using TSV fallback: $TSV_FILE"
        if [ ! -f "$TSV_FILE" ]; then
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                scan_id target severity category title description url status first_seen \
                > "$TSV_FILE"
        fi
    fi
}

# ── Register a scan ───────────────────────────────────────────────────────────

db_register_scan() {
    local target=$1
    local session_dir=${2:-""}
    local mode=${3:-"medium"}
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    if command -v sqlite3 &>/dev/null; then
        CURRENT_SCAN_ID=$(sqlite3 "$DB_FILE" \
            "INSERT INTO scans(target,timestamp,session_dir,mode) \
             VALUES('$(echo "$target" | sed "s/'/''/g")','$ts','$session_dir','$mode'); \
             SELECT last_insert_rowid();")
        export CURRENT_SCAN_ID
        log_debug "DB: registered scan #$CURRENT_SCAN_ID for $target"
    else
        CURRENT_SCAN_ID=$(date +%s)
        export CURRENT_SCAN_ID
    fi
}

# ── Insert or update a finding ────────────────────────────────────────────────
# db_insert_finding <target> <severity> <category> <title> [description] [url]

db_insert_finding() {
    local target=$1
    local severity=$(echo "$2" | tr '[:lower:]' '[:upper:]')
    local category=$3
    local title=$4
    local description=${5:-""}
    local url=${6:-""}
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local scan_id="${CURRENT_SCAN_ID:-0}"

    if command -v sqlite3 &>/dev/null; then
        # Insert new, or update last_seen + scan_id if already known
        sqlite3 "$DB_FILE" <<SQL
INSERT INTO findings(scan_id,target,severity,category,title,description,url,status,first_seen,last_seen)
VALUES(
    $scan_id,
    '$(echo "$target"      | sed "s/'/''/g")',
    '$(echo "$severity"    | sed "s/'/''/g")',
    '$(echo "$category"    | sed "s/'/''/g")',
    '$(echo "$title"       | sed "s/'/''/g")',
    '$(echo "$description" | sed "s/'/''/g")',
    '$(echo "$url"         | sed "s/'/''/g")',
    'new',
    '$ts',
    '$ts'
)
ON CONFLICT(target,category,title) DO UPDATE SET
    last_seen = '$ts',
    scan_id   = $scan_id,
    status    = CASE WHEN status = 'remediated' THEN 'new' ELSE status END;
SQL
    else
        # TSV fallback
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\tnew\t%s\n' \
            "$scan_id" "$target" "$severity" "$category" "$title" \
            "$description" "$url" "$ts" >> "$TSV_FILE"
    fi
}

# ── Bulk import nuclei_results.txt ────────────────────────────────────────────

db_import_nuclei() {
    local session_dir=$1
    local nuclei_file="${session_dir}/nuclei_results.txt"
    [ -s "$nuclei_file" ] || return 0

    local imported=0
    while IFS= read -r line; do
        # Nuclei output format: [template-id] [severity] URL
        local tmpl sev url
        tmpl=$(echo "$line" | grep -oP '(?<=\[)[^\]]+(?=\])' | head -1)
        sev=$(echo "$line"  | grep -oP '(?<=\[)(critical|high|medium|low|info)(?=\])' -i | head -1)
        url=$(echo "$line"  | grep -oE 'https?://[^ ]+' | head -1)
        [ -z "$tmpl" ] && continue
        db_insert_finding \
            "${url:-unknown}" \
            "${sev:-info}" \
            "vuln" \
            "$tmpl" \
            "$line" \
            "$url"
        imported=$((imported + 1))
    done < "$nuclei_file"

    log_info "DB: imported $imported nuclei finding(s)"
}

# ── Query helpers ─────────────────────────────────────────────────────────────

db_new_findings() {
    if command -v sqlite3 &>/dev/null; then
        sqlite3 -separator $'\t' "$DB_FILE" \
            "SELECT severity,category,title,url FROM findings WHERE status='new' ORDER BY severity,category,title;"
    else
        grep $'\tnew\t' "$TSV_FILE" 2>/dev/null || true
    fi
}

db_findings_by_severity() {
    local sev=$(echo "${1:-HIGH}" | tr '[:lower:]' '[:upper:]')
    if command -v sqlite3 &>/dev/null; then
        sqlite3 -separator $'\t' "$DB_FILE" \
            "SELECT target,category,title,url,status FROM findings WHERE severity='$sev' ORDER BY last_seen DESC;"
    else
        grep -i "$sev" "$TSV_FILE" 2>/dev/null || true
    fi
}

# Returns count of findings by severity as: CRITICAL HIGH MEDIUM LOW INFO
db_summary_counts() {
    if command -v sqlite3 &>/dev/null; then
        sqlite3 "$DB_FILE" <<'SQL'
SELECT
    SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END),
    SUM(CASE WHEN severity='HIGH'     THEN 1 ELSE 0 END),
    SUM(CASE WHEN severity='MEDIUM'   THEN 1 ELSE 0 END),
    SUM(CASE WHEN severity='LOW'      THEN 1 ELSE 0 END),
    SUM(CASE WHEN severity='INFO'     THEN 1 ELSE 0 END)
FROM findings WHERE status NOT IN ('suppressed','false_positive');
SQL
    else
        echo "0 0 0 0 0"
    fi
}

# Mark a finding as a false positive (by title substring)
db_mark_false_positive() {
    local title_pattern=$1
    if command -v sqlite3 &>/dev/null; then
        sqlite3 "$DB_FILE" \
            "UPDATE findings SET status='false_positive' WHERE title LIKE '%$(echo "$title_pattern" | sed "s/'/''/g")%';"
        log_info "DB: marked findings matching '$title_pattern' as false_positive"
    fi
}

# Mark a finding as remediated
db_mark_remediated() {
    local title_pattern=$1
    if command -v sqlite3 &>/dev/null; then
        sqlite3 "$DB_FILE" \
            "UPDATE findings SET status='remediated' WHERE title LIKE '%$(echo "$title_pattern" | sed "s/'/''/g")%';"
        log_info "DB: marked findings matching '$title_pattern' as remediated"
    fi
}

# Print a summary table to stdout
db_print_summary() {
    if command -v sqlite3 &>/dev/null; then
        echo ""
        echo "=== Findings Database Summary ==="
        sqlite3 -column -header "$DB_FILE" \
            "SELECT severity, count(*) as count, status FROM findings GROUP BY severity,status ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END;" 2>/dev/null
        echo ""
        echo "Cross-target duplicates:"
        sqlite3 -column -header "$DB_FILE" \
            "SELECT title, count(DISTINCT target) as targets FROM findings GROUP BY title HAVING targets > 1 ORDER BY targets DESC LIMIT 10;" 2>/dev/null
        echo ""
    else
        log_info "Findings TSV: $TSV_FILE"
        wc -l < "$TSV_FILE" && echo "findings total"
    fi
}
