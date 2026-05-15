#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  bash docker/test.sh <provider> [pkcs11-check options...] [-- <targets...>]

Examples:
  bash docker/test.sh opencryptoki
  bash docker/test.sh softhsm2 --match test_interface
  bash docker/test.sh nss --timeout 30 -- src/pkcs11_check/testcases/test_interface.py

Provider names may be given with or without the `test-` prefix.
EOF
}

if [[ $# -lt 1 ]]; then
    usage >&2
    exit 2
fi

provider="$1"
shift

if [[ "$provider" == "help" || "$provider" == "--help" || "$provider" == "-h" ]]; then
    usage
    exit 0
fi

service="$provider"
if [[ "$service" != test-* ]]; then
    service="test-$service"
fi

# Warn if test vector data is not present
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ ! -d "$PROJECT_ROOT/data/wycheproof" ] && [ ! -d "$PROJECT_ROOT/data/acvp" ]; then
    echo "Warning: No test vector data found in data/. Vector tests will be skipped." >&2
    echo "  Run: pkcs11-check fetch-data all" >&2
    echo "" >&2
fi

option_args=()
target_args=()
rebuild_flag=""
split_targets=0

for arg in "$@"; do
    if [[ "$arg" == "--" && $split_targets -eq 0 ]]; then
        split_targets=1
        continue
    fi

    if [[ "$arg" == "--rebuild" && $split_targets -eq 0 ]]; then
        rebuild_flag="--rebuild"
        continue
    fi

    if [[ $split_targets -eq 0 ]]; then
        option_args+=("$arg")
    else
        target_args+=("$arg")
    fi
done

compose_args=(docker compose -f docker/docker-compose.test.yml run --rm)

if [[ ${#option_args[@]} -gt 0 ]]; then
    printf -v serialized_options '%q ' "${option_args[@]}"
    compose_args+=(-e "PKCS11_CHECK_EXTRA_ARGS=${serialized_options% }")
fi

if [[ ${#target_args[@]} -gt 0 ]]; then
    printf -v serialized_targets '%q ' "${target_args[@]}"
    compose_args+=(-e "PKCS11_CHECK_TARGETS=${serialized_targets% }")
fi

if [[ -n "$rebuild_flag" ]]; then
    echo "Rebuilding $service from scratch (no cache)..."
    docker compose -f docker/docker-compose.test.yml rm --force --stop "$service" 2>/dev/null || true
    docker compose -f docker/docker-compose.test.yml build --no-cache "$service"
fi

compose_args+=(--build "$service")

exec "${compose_args[@]}"
