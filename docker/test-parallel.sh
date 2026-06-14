#!/usr/bin/env bash
# Run a provider's full test round as a POOL: split the test files into M
# balanced batches and run them through N concurrent containers (a finished
# worker grabs the next pending batch). PKCS#11-safe: each container is a fully
# self-contained instance (its own server + token on its own localhost), one
# serial test process over a DISJOINT subset of files. No concurrent same-token
# access; full OS isolation between batches.
#
# M batches > N workers keeps all N cores busy even when batches are uneven,
# so the tail shrinks toward max(largest_batch, total_work / N).
#
# Usage:
#   docker/test-parallel.sh <provider> [--shards M] [--concurrency N] \
#                           [--prior-results PATH] [--testcases DIR] [-- pytest-args...]
#
#   --shards M       number of data batches (file partitions). Default: = concurrency.
#   --concurrency N  max simultaneous containers. Default: cores/4 (avoids
#                    oversubscription; each shard uses ~2-4 cores).
#
# Example (8 batches, 4 at a time):
#   docker/test-parallel.sh bouncyhsm --shards 8 --concurrency 4 \
#       --prior-results artifacts/bouncyhsm-clean/results.json
#
# Output: artifacts/<provider>-pooled/{results,coverage,quality}.json + report.jsonl
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

provider="${1:?usage: test-parallel.sh <provider> [--shards M] [--concurrency N]}"
shift
service="$provider"
[[ "$service" == test-* ]] || service="test-$provider"

cores="$(nproc 2>/dev/null || echo 4)"
concurrency=$(( cores / 4 )); (( concurrency < 2 )) && concurrency=2
shards=0          # 0 => default to concurrency
prior=""
testcases="src/pkcs11_check/testcases"
extra_args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --shards) shards="$2"; shift 2 ;;
        --concurrency|-j) concurrency="$2"; shift 2 ;;
        --prior-results) prior="$2"; shift 2 ;;
        --testcases) testcases="$2"; shift 2 ;;
        --) shift; extra_args=("$@"); break ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
(( shards == 0 )) && shards="$concurrency"
(( shards < 1 )) && { echo "shards must be >= 1" >&2; exit 2; }
(( concurrency < 1 )) && concurrency=1
(( concurrency > shards )) && concurrency="$shards"

echo "=== planning $shards batches, $concurrency concurrent (host has $cores cores) ==="
# Default = simple even count-balanced chunks. The M>N pool absorbs the resulting
# imbalance (a worker that finishes early just pulls the next chunk), so precise
# balancing is unnecessary — and a noisy/foreign duration oracle can make it
# WORSE. Pass --prior-results <this-provider's results.json> only if you want
# tighter duration-based packing (advanced; must be the SAME provider, since skip
# patterns and thus per-file durations differ per provider).
prior_arg=()
if [[ -n "$prior" && -f "$prior" ]]; then
    prior_arg=(--prior-results "$prior")
    echo "  balance: duration-oracle ($prior)"
else
    echo "  balance: even count chunks (simple; pool absorbs imbalance)"
fi
mapfile -t LINES < <(uv run pkcs11-check shard-units --shards "$shards" --testcases "$testcases" "${prior_arg[@]}" --format lines)
if [[ "${#LINES[@]}" -ne "$shards" ]]; then
    echo "ERROR: expected $shards batch lines, got ${#LINES[@]}" >&2
    exit 1
fi

# Materialize batch file-lists + verify the partition is COMPLETE (nothing dropped).
batchdir="artifacts/${provider}-batches"
rm -rf "$batchdir"; mkdir -p "$batchdir"
batched_total=0
for i in "${!LINES[@]}"; do
    # word-split the space-separated line into one path per output line
    # shellcheck disable=SC2086
    printf '%s\n' ${LINES[$i]} > "$batchdir/batch-${i}.txt"
    n=$(grep -c . "$batchdir/batch-${i}.txt" || true)
    batched_total=$(( batched_total + n ))
    echo "  batch $i: $n files"
done
discovered=$(find "$testcases" -name 'test_*.py' | wc -l)
echo "  partition check: batched=$batched_total  discovered=$discovered"
if [[ "$batched_total" -ne "$discovered" ]]; then
    echo "ERROR: batch partition incomplete ($batched_total != $discovered) — refusing to drop tests" >&2
    exit 1
fi

# Clean prior shard artifact dirs (may be root-owned from a previous container run).
# --network none: this helper only touches a mounted volume; keep it isolated like every
# other container in the suite (no target gets network at run time).
docker run --rm --network none -v "$PROJECT_ROOT/artifacts:/artifacts" busybox sh -c \
    "rm -rf /artifacts/${provider}-shard-*" 2>/dev/null || true

artifact_owner="${PKCS11_CHECK_ARTIFACT_OWNER:-$(id -u):$(id -g)}"

# One worker: run batch $1 in its own container against its own server+token.
run_one_batch() {
    local i="$1"
    local files targets
    files="$(tr '\n' ' ' < "${BATCHDIR}/batch-${i}.txt")"
    targets="$files"
    [[ -n "${EXTRA_ARGS:-}" ]] && targets="$files ${EXTRA_ARGS}"
    docker compose -f docker/docker-compose.test.yml run --rm \
        -e PKCS11_CHECK_TARGETS="$targets" \
        -e PKCS11_CHECK_ARTIFACT_DIR="/artifacts/${PROVIDER}-shard-${i}" \
        -e PKCS11_CHECK_ARTIFACT_OWNER="$ARTIFACT_OWNER" \
        "$SERVICE" > "/tmp/${PROVIDER}-shard-${i}.log" 2>&1
}
export -f run_one_batch
export PROVIDER="$provider" SERVICE="$service" BATCHDIR="$batchdir" EXTRA_ARGS="${extra_args[*]:-}"
export ARTIFACT_OWNER="$artifact_owner"

echo "=== running $shards batches through $concurrency workers ==="
start=$(date +%s)
xrc=0
seq 0 $(( shards - 1 )) | xargs -P "$concurrency" -I {} bash -c 'run_one_batch "$@"' _ {} || xrc=$?
end=$(date +%s)
echo "=== pool done: wall=$((end-start))s ($(( (end-start)/60 ))m$(( (end-start)%60 ))s)  (xargs rc=$xrc) ==="

# Completeness: every batch must have produced a results.json — nothing forgotten.
shard_dirs=()
missing=0
for i in $(seq 0 $(( shards - 1 ))); do
    d="artifacts/${provider}-shard-${i}"
    shard_dirs+=("$d")
    if [[ ! -f "$d/results.json" ]]; then
        echo "MISSING: batch $i produced no results.json (see /tmp/${provider}-shard-${i}.log)" >&2
        missing=1
    fi
done
(( missing )) && echo "WARN: some batches produced no output — results would be incomplete!" >&2

echo "=== merging $shards batches ==="
uv run pkcs11-check merge-shards "${shard_dirs[@]}" -o "artifacts/${provider}-pooled"
echo "=== pooled wall=$((end-start))s, $shards batches / $concurrency workers -> artifacts/${provider}-pooled ==="
exit "$(( missing ? 1 : 0 ))"
