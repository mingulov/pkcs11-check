#!/usr/bin/env bash
# Run p11test against a locally-built soft token.
# Usage: bash local-builds/test.sh <target> [pytest-args...]
#
# Targets:
#   kryoptic        — locally-built Kryoptic v1.5.0
#   softhsm2-local  — locally-built SoftHSM2 2.7.0
#   softhsm2-system — system SoftHSM2 (Ubuntu package, 2.6.1)
#   pkcs11-mock     — locally-built pkcs11-mock
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TOKENS_DIR="$SCRIPT_DIR/tokens"
mkdir -p "$TOKENS_DIR"

TARGET="${1:-}"
shift 2>/dev/null || true  # remaining args passed to pytest

setup_kryoptic() {
    local so="$SCRIPT_DIR/kryoptic/lib/libkryoptic_pkcs11.so"
    [ -f "$so" ] || { echo "ERROR: Build kryoptic first: bash local-builds/build.sh kryoptic"; exit 1; }

    local token_dir="$TOKENS_DIR/kryoptic"
    mkdir -p "$token_dir"

    local conf="$token_dir/token.conf"
    cat > "$conf" <<TOML
[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "$token_dir/token.sql"
TOML

    # Initialize token if not already done
    if [ ! -f "$token_dir/token.sql" ]; then
        echo "Initializing Kryoptic token..."
        KRYOPTIC_CONF="$conf" pkcs11-tool --module "$so" \
            --init-token --label "p11test" --so-pin 12345678 2>/dev/null || true
        KRYOPTIC_CONF="$conf" pkcs11-tool --module "$so" \
            --init-pin --pin 1234 --so-pin 12345678 2>/dev/null || true
    fi

    export KRYOPTIC_CONF="$conf"
    MODULE="$so"
    PIN="1234"
}

setup_softhsm2_local() {
    local so="$SCRIPT_DIR/softhsm2/lib/libsofthsm2.so"
    [ -f "$so" ] || { echo "ERROR: Build softhsm2 first: bash local-builds/build.sh softhsm2"; exit 1; }

    local token_dir="$TOKENS_DIR/softhsm2-local"
    mkdir -p "$token_dir"

    local conf="$token_dir/softhsm2.conf"
    cat > "$conf" <<EOF
directories.tokendir = $token_dir/tokens
objectstore.backend = file
log.level = WARNING
EOF
    mkdir -p "$token_dir/tokens"

    # Initialize token if empty
    if [ -z "$(ls -A "$token_dir/tokens" 2>/dev/null)" ]; then
        echo "Initializing SoftHSM2 (local build) token..."
        SOFTHSM2_CONF="$conf" softhsm2-util --init-token --slot 0 \
            --label "p11test" --pin 1234 --so-pin 12345678 2>/dev/null || \
        SOFTHSM2_CONF="$conf" "$SCRIPT_DIR/softhsm2/install/bin/softhsm2-util" --init-token --slot 0 \
            --label "p11test" --pin 1234 --so-pin 12345678
    fi

    export SOFTHSM2_CONF="$conf"
    MODULE="$so"
    PIN="1234"
}

setup_softhsm2_system() {
    local so="/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
    [ -f "$so" ] || { echo "ERROR: System SoftHSM2 not found"; exit 1; }

    local conf="/tmp/p11test-softhsm2.conf"
    if [ ! -f "$conf" ]; then
        bash "$PROJECT_DIR/scripts/setup-softhsm.sh"
    fi

    export SOFTHSM2_CONF="$conf"
    MODULE="$so"
    PIN="1234"
}

setup_pkcs11_mock() {
    local so="$SCRIPT_DIR/pkcs11-mock/lib/pkcs11-mock.so"
    [ -f "$so" ] || { echo "ERROR: Build pkcs11-mock first: bash local-builds/build.sh pkcs11-mock"; exit 1; }

    MODULE="$so"
    PIN=""  # pkcs11-mock doesn't need PIN
}

case "$TARGET" in
    kryoptic)        setup_kryoptic ;;
    softhsm2-local)  setup_softhsm2_local ;;
    softhsm2-system) setup_softhsm2_system ;;
    softhsm2)        setup_softhsm2_system ;;  # default to system
    pkcs11-mock)     setup_pkcs11_mock ;;
    *)
        echo "Usage: $0 <target> [pytest-args...]"
        echo ""
        echo "Targets:"
        echo "  kryoptic        — locally-built Kryoptic v1.5.0"
        echo "  softhsm2-local  — locally-built SoftHSM2 2.7.0"
        echo "  softhsm2-system — system SoftHSM2 (Ubuntu 2.6.1)"
        echo "  softhsm2        — alias for softhsm2-system"
        echo "  pkcs11-mock     — locally-built pkcs11-mock"
        echo ""
        echo "Examples:"
        echo "  $0 kryoptic                    # full suite"
        echo "  $0 kryoptic -k test_encrypt -v # specific tests"
        echo "  $0 softhsm2 -x --tb=short      # stop on first failure"
        exit 1
        ;;
esac

echo "=== Running p11test ==="
echo "Module: $MODULE"
echo "PIN: ${PIN:-<none>}"
echo ""

cd "$PROJECT_DIR"

PYTEST_ARGS=(
    src/p11test/testcases/
    "--p11-module=$MODULE"
    "--benchmark-disable"
)
[ -n "${PIN:-}" ] && PYTEST_ARGS+=("--p11-pin=$PIN")

# Append any extra args from command line
PYTEST_ARGS+=("$@")

exec uv run pytest "${PYTEST_ARGS[@]}"
