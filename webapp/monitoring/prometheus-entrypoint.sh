#!/bin/sh
set -eu
test -n "${METRICS_BEARER_TOKEN:-}"
escaped=$(printf '%s' "$METRICS_BEARER_TOKEN" | sed 's/[&|]/\\&/g')
sed "s|__METRICS_TOKEN__|$escaped|g" /etc/prometheus/prometheus.yml.template > /tmp/prometheus.yml
exec /bin/prometheus --config.file=/tmp/prometheus.yml --storage.tsdb.path=/prometheus
