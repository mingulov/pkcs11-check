#!/usr/bin/env bash
# Run a provider's full test round across N parallel containers (shards), then
# merge the results. PKCS#11-safe: each container is a fully self-contained
# instance (its own server + token on its own localhost), driven by one serial
# test process over a DISJOINT subset of the test files. No concurrent
# same-token access; full OS isolation between shards.
#
# Usage:
#   docker/test-parallel.sh <provider> [--shards N] [--prior-results PATH] [-- pytest-args...]
#
# Example:
#   docker/test-parallel.sh bouncyhsm --shards 4 \
#       --prior-results artifacts/bouncyhsm-clean/results.json
#
# Output: artifacts/<provider>-pooled/{results,coverage,quality}.json + report.jsonl
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

provider="${1:?usage: test-parallel.sh <provider> [--shards N] [--prior-results PATH]}"
shift
service="$provider"
[[ "$service" == test-* ]] || service="test-$provider"

# Default shard count is core-aware: each shard (server + crypto + pytest) uses
# ~2-4 cores, so oversubscribing the host slows every shard. ~4 cores/shard
# keeps them near solo speed. Override with --shards.
_cores="$(nproc 2>/dev/null || echo 4)"
shards=$(( _cores / 4 )); (( shards < 2 )) && shards=2
prior=""
extra_args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --shards) shards="$2"; shift 2 ;;
        --prior-results) prior="$2"; shift 2 ;;
        --) shift; extra_args=("$@"); break ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

compose=(docker compose -f docker/docker-compose.test.yml)

echo "=== planning $shards shards for $provider ==="
prior_arg=()
[[ -n "$prior" && -f "$prior" ]] && prior_arg=(--prior-results "$prior")
mapfile -t SHARD_LINES < <(uv run pkcs11-check shard-units --shards "$shards" "${prior_arg[@]}" --format lines)
if [[ "${#SHARD_LINES[@]}" -ne "$shards" ]]; then
    echo "ERROR: expected $shards shard lines, got ${#SHARD_LINES[@]}" >&2
    exit 1
fi
for i in "${!SHARD_LINES[@]}"; do
    echo "  shard $i: $(wc -w <<<"${SHARD_LINES[$i]}") files"
done

# Clean prior shard artifact dirs (may be root-owned from a previous container run).
shard_dirs=()
for i in "${!SHARD_LINES[@]}"; do shard_dirs+=("artifacts/${provider}-shard-${i}"); done
docker run --rm -v "$PROJECT_ROOT/artifacts:/artifacts" busybox sh -c \
    "rm -rf $(printf '/artifacts/%s-shard-* ' "$provider")" 2>/dev/null || true

echo "=== launching $shards containers in parallel ==="
start=$(date +%s)
pids=()
for i in "${!SHARD_LINES[@]}"; do
    files="${SHARD_LINES[$i]}"
    targets="$files"
    [[ ${#extra_args[@]} -gt 0 ]] && targets="$files ${extra_args[*]}"
    "${compose[@]}" run --rm \
        -e PKCS11_CHECK_TARGETS="$targets" \
        -e PKCS11_CHECK_ARTIFACT_DIR="/artifacts/${provider}-shard-${i}" \
        "$service" >"/tmp/${provider}-shard-${i}.log" 2>&1 &
    pids+=("$!")
done

rc=0
for idx in "${!pids[@]}"; do
    if ! wait "${pids[$idx]}"; then
        echo "shard $idx exited non-zero (rc preserved; see /tmp/${provider}-shard-${idx}.log)" >&2
        rc=1
    fi
done
end=$(date +%s)
echo "=== all shards done: wall=$((end-start))s ($(( (end-start)/60 ))m$(( (end-start)%60 ))s) ==="

echo "=== merging shards ==="
uv run pkcs11-check merge-shards "${shard_dirs[@]}" -o "artifacts/${provider}-pooled"

echo "=== pooled wall=$((end-start))s -> artifacts/${provider}-pooled ==="
exit "$rc"
