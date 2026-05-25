#!/usr/bin/env bash
# Run docker/test.sh for multiple providers, passing shared arguments to each.
#
# Usage:
#   bash docker/test-all.sh                                    # default targets
#   bash docker/test-all.sh softhsm2 kryoptic                 # specific targets
#   bash docker/test-all.sh -- src/pkcs11_check/testcases/test_interface.py
#   bash docker/test-all.sh softhsm2 nss -- test_interop
#   bash docker/test-all.sh --all                              # every target
#
# Arguments before "--" that match a known provider are treated as targets.
# Everything else (before and after "--") is forwarded to docker/test.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DEFAULT_PROVIDERS=(
    kryoptic-main
    softhsm2-main
    nss-main
    opencryptoki-master
    tpm2
    bouncyhsm
)

ALL_PROVIDERS=(
    softhsm2 softhsm2-generated-iv softhsm2-main
    kryoptic kryoptic-main kryoptic-fips
    nss nss-pqc nss-main
    opencryptoki opencryptoki-master
    bouncyhsm
    tpm2
    pkcs11-mock
)

_is_provider() {
    local name="${1#test-}"
    for t in "${ALL_PROVIDERS[@]}"; do
        [[ "$name" == "$t" ]] && return 0
    done
    return 1
}

# --- Parse arguments: split providers from shared args ---
providers=()
shared_args=()
past_separator=0

for arg in "$@"; do
    if [[ "$arg" == "--" && $past_separator -eq 0 ]]; then
        past_separator=1
        shared_args+=("--")
        continue
    fi

    if [[ $past_separator -eq 1 ]]; then
        shared_args+=("$arg")
    elif [[ "$arg" == "--all" ]]; then
        providers=("${ALL_PROVIDERS[@]}")
    elif [[ $past_separator -eq 0 ]] && _is_provider "$arg"; then
        providers+=("${arg#test-}")
    else
        shared_args+=("$arg")
    fi
done

if [[ ${#providers[@]} -eq 0 ]]; then
    providers=("${DEFAULT_PROVIDERS[@]}")
fi

echo "=== pkcs11-check Docker test matrix ==="
echo "Targets: ${providers[*]}"
[[ ${#shared_args[@]} -gt 0 ]] && echo "Args:    ${shared_args[*]}"
echo ""

# --- Run each provider ---
failed=()
passed=()

for provider in "${providers[@]}"; do
    echo ""
    echo "================================================================"
    echo "  $provider"
    echo "================================================================"
    if bash "$SCRIPT_DIR/test.sh" "$provider" "${shared_args[@]}"; then
        passed+=("$provider")
    else
        failed+=("$provider")
    fi
done

# --- Summary ---
echo ""
echo "=== Summary ==="
echo "Passed: ${#passed[@]}/${#providers[@]} (${passed[*]:-none})"
if [[ ${#failed[@]} -gt 0 ]]; then
    echo "Failed: ${#failed[@]}/${#providers[@]} (${failed[*]})"
    exit 1
fi
