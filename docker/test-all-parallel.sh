#!/usr/bin/env bash
# Run a SHARDED full round for each provider and print a comparison summary.
# For each provider: rebuild its image (picks up the current tree's fixes), then
# run docker/test-parallel.sh with the given batch/worker counts; record wall +
# outcome counts. Providers run sequentially (each provider's pool already uses
# the host's cores); the script continues past a provider that fails.
#
# Usage:
#   docker/test-all-parallel.sh [--shards M] [--concurrency N] [--no-build] [providers...]
#
# Defaults: --shards 8 --concurrency 3, the stable provider set.
set -uo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

shards=8
concurrency=3
do_build=1
providers=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --shards) shards="$2"; shift 2 ;;
        --concurrency|-j) concurrency="$2"; shift 2 ;;
        --no-build) do_build=0; shift ;;
        *) providers+=("$1"); shift ;;
    esac
done
if [[ ${#providers[@]} -eq 0 ]]; then
    providers=(softhsm2 kryoptic nss nss-pqc opencryptoki bouncyhsm pkcs11-mock tpm2)
fi

summary="/tmp/all-parallel-summary.txt"
: > "$summary"
printf '%-22s %7s %8s %8s %8s %8s %8s\n' provider wall_s total passed failed crashed timeout | tee -a "$summary"
printf '%-22s %7s %8s %8s %8s %8s %8s\n' "----------------------" "------" "-------" "-------" "-------" "-------" "-------" | tee -a "$summary"

overall_start=$(date +%s)
for p in "${providers[@]}"; do
    echo "############################################################"
    echo "### provider: $p  ($(date -Is))"
    echo "############################################################"
    if [[ "$do_build" -eq 1 ]]; then
        echo "--- building test-$p (picks up current-tree fixes) ---"
        if ! docker compose -f docker/docker-compose.test.yml build "test-$p" > "/tmp/all-build-$p.log" 2>&1; then
            echo "BUILD FAILED for $p (see /tmp/all-build-$p.log)"
            printf '%-22s %7s %8s %8s %8s %8s %8s\n' "$p" "BUILD-FAIL" - - - - - | tee -a "$summary"
            continue
        fi
    fi
    pstart=$(date +%s)
    bash docker/test-parallel.sh "$p" --shards "$shards" --concurrency "$concurrency" \
        > "/tmp/all-run-$p.log" 2>&1
    prc=$?
    pend=$(date +%s)
    pwall=$(( pend - pstart ))
    res="artifacts/${p}-pooled/results.json"
    if [[ -f "$res" ]]; then
        # shellcheck disable=SC2016
        read -r total passed failed crashed timeout < <(
            python3 -c "import json,sys; s=json.load(open('$res'))['summary']; print(s.get('total',0),s.get('passed',0),s.get('failed',0),s.get('crashed',0),s.get('timeout',0))"
        )
        printf '%-22s %7d %8s %8s %8s %8s %8s\n' "$p" "$pwall" "$total" "$passed" "$failed" "$crashed" "$timeout" | tee -a "$summary"
    else
        printf '%-22s %7d %8s %8s %8s %8s %8s\n' "$p" "$pwall" "NO-RESULTS(rc=$prc)" - - - - | tee -a "$summary"
    fi
done
overall_end=$(date +%s)
echo
echo "=== ALL-PROVIDERS SHARDED ($shards batches / $concurrency workers) — total wall $(( (overall_end-overall_start)/60 ))m ==="
cat "$summary"
