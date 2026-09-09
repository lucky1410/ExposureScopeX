#!/bin/sh
set -eu

TEMPLATE_HOME="${NUCLEI_TEMPLATES_DIR:-/app/runtime/nuclei-templates}"
COMMUNITY_HOME="${NUCLEI_COMMUNITY_TEMPLATES_DIR:-/app/runtime/nuclei-templates-community}"
REPOS="${NUCLEI_EXTRA_TEMPLATE_REPOS:-${NUCLEI_TEMPLATE_REPOS:-}}"
AUTOUPDATE="${NUCLEI_TEMPLATE_AUTOUPDATE:-true}"
REFRESH_HOURS="${NUCLEI_TEMPLATE_REFRESH_HOURS:-24}"
FORCE_UPDATE="${NUCLEI_TEMPLATE_FORCE_UPDATE:-false}"
OFFICIAL_STAMP="$TEMPLATE_HOME/.last-update"
COMMUNITY_STAMP="$COMMUNITY_HOME/.last-update"
UPDATE_LOCK="/app/runtime/.template-update.lock"

mkdir -p "$TEMPLATE_HOME" "$COMMUNITY_HOME" /app/runtime/.config /app/runtime/.cache

should_refresh() {
  stamp="$1"
  if [ "$FORCE_UPDATE" = "true" ]; then
    return 0
  fi
  if [ "$AUTOUPDATE" != "true" ]; then
    return 1
  fi
  if [ ! -f "$stamp" ]; then
    return 0
  fi
  now_epoch=$(date +%s)
  stamp_epoch=$(date -r "$stamp" +%s 2>/dev/null || echo 0)
  max_age=$((REFRESH_HOURS * 3600))
  [ $((now_epoch - stamp_epoch)) -ge "$max_age" ]
}

refresh_templates() (
  if ! mkdir "$UPDATE_LOCK" 2>/dev/null; then
    echo "[templates] another template update is already running"
    exit 0
  fi
  trap 'rmdir "$UPDATE_LOCK" 2>/dev/null || true' EXIT INT TERM

  if should_refresh "$OFFICIAL_STAMP"; then
    echo "[templates] refreshing official nuclei templates"
    if nuclei -update-templates >/tmp/nuclei-update.log 2>&1; then
      touch "$OFFICIAL_STAMP"
    else
      cat /tmp/nuclei-update.log
      echo "[templates] official template refresh failed; it will be retried" >&2
    fi
  else
    echo "[templates] official nuclei templates are still fresh"
  fi

  if [ -n "$REPOS" ] && should_refresh "$COMMUNITY_STAMP"; then
    failed=0
    old_ifs="$IFS"
    IFS=','
    for repo in $REPOS; do
      repo_trimmed=$(printf '%s' "$repo" | xargs)
      [ -n "$repo_trimmed" ] || continue
      case "$repo_trimmed" in
        *"<"*|*">"*)
          echo "[templates] skipping placeholder repository $repo_trimmed"
          continue
          ;;
        *"/projectdiscovery/nuclei-templates"*|*"projectdiscovery/nuclei-templates.git"*)
          echo "[templates] skipping duplicate official repository $repo_trimmed"
          continue
          ;;
      esac
      name=$(basename "$repo_trimmed" .git)
      dest="$COMMUNITY_HOME/$name"
      if [ -d "$dest/.git" ]; then
        echo "[templates] refreshing community repository $repo_trimmed"
        if git -C "$dest" fetch --depth 1 origin && git -C "$dest" reset --hard FETCH_HEAD; then
          git -C "$dest" reflog expire --expire=now --all || true
          git -C "$dest" gc --prune=now --quiet || true
        else
          failed=1
        fi
      elif ! git clone --depth 1 "$repo_trimmed" "$dest"; then
        failed=1
      fi
    done
    IFS="$old_ifs"
    if [ "$failed" -eq 0 ]; then
      touch "$COMMUNITY_STAMP"
    else
      echo "[templates] one or more community updates failed; they will be retried" >&2
    fi
  fi
)

if [ "${1:-}" = "update-templates" ]; then
  AUTOUPDATE=true
  FORCE_UPDATE=true
  refresh_templates
  exit 0
fi

refresh_templates
exec "$@"
