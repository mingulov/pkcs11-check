#!/usr/bin/env bash
# scripts/docker-rerun.sh -- re-run one Docker target into a NEW artifact
# dir, preserving baseline. After the rerun:
#   1. recheck-summary.py prints a one-line summary delta
#   2. compare-results.py detects per-file regressions (exit 1 if found)
#
# Usage: scripts/docker-rerun.sh <target> [extra docker compose args...]
# Example: scripts/docker-rerun.sh softhsm2
#
# Preserves the 2026-05-27 baseline by refusing to overwrite an existing
# date-tagged output dir. To re-run on the same day, rename the prior
# attempt: `mv artifacts/<target>-recheck-YYYYMMDD{,-1}` then re-run.
set -euo pipefail

target="${1:?usage: docker-rerun.sh <target> [extra docker compose args]}"
shift || true
date_tag="$(date +%Y%m%d)"
out_dir="artifacts/${target}-recheck-${date_tag}"

if [ -e "$out_dir" ]; then
  echo "REFUSE: $out_dir exists. To re-run today, rename first:" >&2
  echo "  mv $out_dir ${out_dir}-1" >&2
  exit 1
fi

docker compose -f docker/docker-compose.test.yml run --rm \
  -v "$HOME/.local/share/pkcs11-check/data:/app/data:ro" \
  -e "PKCS11_CHECK_ARTIFACT_DIR=/artifacts/${target}-recheck-${date_tag}" \
  --build "test-${target}" "$@"

baseline="artifacts/${target}/results.json"
current="${out_dir}/results.json"
if [ ! -f "$baseline" ] || [ ! -f "$current" ]; then
  echo "WARN: missing $baseline or $current; skipping comparison" >&2
  exit 0
fi

echo
echo "=== Summary delta (informational) ==="
uv run python scripts/recheck-summary.py "$target" "$baseline" "$current"
echo
echo "=== Per-file regression check ==="
uv run python scripts/compare-results.py "$baseline" "$current"
