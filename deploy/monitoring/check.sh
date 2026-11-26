#!/usr/bin/env bash
# Checks the alert rules: promtool syntax and unit tests, every metric name
# declared somewhere in Core or relay source, and the Helm chart's copy
# identical when the chart repository sits next to this one.
#
#   deploy/monitoring/check.sh
#
# promtool comes from PATH, else from the pinned Prometheus image (Docker).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
rules="meshtransit-rules.yaml"
image="prom/prometheus:v3.5.0"

run_promtool() {
  if command -v promtool >/dev/null 2>&1; then
    (cd "$here" && command promtool "$@")
  else
    docker run --rm -v "$here:/rules:ro" -w /rules --entrypoint promtool "$image" "$@"
  fi
}

run_promtool check rules "$rules"
run_promtool test rules meshtransit-rules.test.yaml

# Every meshtransit_/meshrelay_ name in an expression must appear in Go
# source (a declaration, or a comment naming a composed name). Histogram
# suffixes map to their base name; regex fragments ending in "_" are skipped,
# and so is meshtransit_role, the scrape target label (not a metric).
missing=0
while read -r name; do
  [ "$name" = meshtransit_role ] && continue
  base="${name%_bucket}"; base="${base%_count}"; base="${base%_sum}"
  if ! grep -rqF --include='*.go' "$base" "$repo/core" "$repo/relay"; then
    echo "unknown metric in $rules: $name" >&2
    missing=1
  fi
done < <(grep -E '^\s+expr:|^\s{10,}[^ :#][^:]*$' "$here/$rules" |
  grep -oE '\b(meshtransit|meshrelay)_[a-z0-9_]*[a-z0-9]\b' | sort -u)
[ "$missing" -eq 0 ] || exit 1

chart_copy="$repo/../meshtransit-core-chart/files/monitoring/$rules"
if [ -f "$chart_copy" ]; then
  if ! cmp -s "$here/$rules" "$chart_copy"; then
    echo "chart copy differs: cp $here/$rules $chart_copy" >&2
    exit 1
  fi
  echo "chart copy identical"
else
  echo "chart repository not found next to this one; copy not compared"
fi
echo "alert rules OK"
