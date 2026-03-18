#!/usr/bin/env bash
# Run p11test against a locally-built soft token.
# Usage: bash local-builds/test.sh <target> [pytest-args...]
#
# Each provider is defined in local-builds/providers/<name>.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export BASE_DIR="$SCRIPT_DIR"
export PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
export TOKENS_DIR="$SCRIPT_DIR/tokens"
mkdir -p "$TOKENS_DIR"

PROVIDERS_DIR="$SCRIPT_DIR/providers"

TARGET="${1:-}"
shift 2>/dev/null || true

_load_provider() {
    local name="$1"
    local provider_file="$PROVIDERS_DIR/$name.sh"
    [ -f "$provider_file" ] || { echo "ERROR: Unknown provider '$name'. Available:"; _list_providers; exit 1; }
    source "$provider_file"
}

_list_providers() {
    for f in "$PROVIDERS_DIR"/*.sh; do
        local name=$(basename "$f" .sh)
        [ "$name" = "openssl" ] && continue  # not a PKCS#11 provider
        local desc=$(grep "^#.*—" "$f" | head -1 | sed 's/^# *//')
        printf "  %-16s %s\n" "$name" "$desc"
    done
}

# Handle aliases and variants
SETUP_FUNC="setup"
case "$TARGET" in
    softhsm2-system)
        TARGET="softhsm2"
        SETUP_FUNC="setup_system"
        ;;
    softhsm2-local)
        TARGET="softhsm2"
        ;;
    tpm2)
        TARGET="tpm2-pkcs11"
        ;;
esac

if [ -z "$TARGET" ] || [ "$TARGET" = "help" ] || [ "$TARGET" = "--help" ]; then
    echo "Usage: $0 <target> [pytest-args...]"
    echo ""
    echo "Available providers:"
    _list_providers
    echo "  softhsm2-local  — locally-built SoftHSM2"
    echo "  softhsm2-system — system SoftHSM2 (Ubuntu package)"
    echo ""
    echo "Examples:"
    echo "  $0 kryoptic                      # full suite"
    echo "  $0 kryoptic -k test_encrypt -v   # specific tests"
    echo "  $0 softhsm2-local -x --tb=short  # stop on first fail"
    exit 1
fi

_load_provider "$TARGET"
$SETUP_FUNC

echo "=== Running p11test ==="
echo "Provider: $PROVIDER_NAME"
echo "Module:   $MODULE"
echo "PIN:      ${PIN:-<none>}"
echo ""

cd "$PROJECT_DIR"

# Export provider-specific environment variables (e.g., NSS_LIB_PARAMS)
if type -t get_env &>/dev/null; then
    while IFS= read -r envline; do
        [ -n "$envline" ] && export "$envline"
    done < <(get_env)
fi

PYTEST_ARGS=(src/p11test/testcases/ "--p11-module=$MODULE" "--benchmark-disable")
[ -n "${PIN:-}" ] && PYTEST_ARGS+=("--p11-pin=$PIN")
# Provider may specify a slot
if type -t get_slot &>/dev/null; then
    local_slot="$(get_slot)"
    [ -n "${local_slot:-}" ] && PYTEST_ARGS+=("--p11-slot=$local_slot")
fi
PYTEST_ARGS+=("$@")

exec uv run pytest "${PYTEST_ARGS[@]}"
