#!/usr/bin/env bash
# Run p11test against a locally-built soft token.
# Usage: bash local-builds/test.sh <target> [pytest-args...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TOKENS_DIR="$SCRIPT_DIR/tokens"
mkdir -p "$TOKENS_DIR"

TARGET="${1:-}"
shift 2>/dev/null || true

setup_kryoptic() {
    local so="$SCRIPT_DIR/kryoptic/lib/libkryoptic_pkcs11.so"
    [ -f "$so" ] || { echo "ERROR: Build first: bash local-builds/build.sh kryoptic"; exit 1; }
    local token_dir="$TOKENS_DIR/kryoptic"
    mkdir -p "$token_dir"
    local conf="$token_dir/token.conf"
    cat > "$conf" <<TOML
[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "$token_dir/token.sql"
TOML
    if [ ! -f "$token_dir/token.sql" ]; then
        echo "Initializing Kryoptic token..."
        KRYOPTIC_CONF="$conf" pkcs11-tool --module "$so" \
            --init-token --label "p11test" --so-pin 12345678 2>/dev/null || true
        KRYOPTIC_CONF="$conf" pkcs11-tool --module "$so" \
            --init-pin --pin 1234 --so-pin 12345678 2>/dev/null || true
    fi
    export KRYOPTIC_CONF="$conf"
    MODULE="$so"; PIN="1234"
}

setup_softhsm2_local() {
    local so="$SCRIPT_DIR/softhsm2/lib/libsofthsm2.so"
    [ -f "$so" ] || { echo "ERROR: Build first: bash local-builds/build.sh softhsm2"; exit 1; }
    local token_dir="$TOKENS_DIR/softhsm2-local"
    mkdir -p "$token_dir/tokens"
    local conf="$token_dir/softhsm2.conf"
    cat > "$conf" <<EOF
directories.tokendir = $token_dir/tokens
objectstore.backend = file
log.level = WARNING
EOF
    if [ -z "$(ls -A "$token_dir/tokens" 2>/dev/null)" ]; then
        echo "Initializing SoftHSM2 (local build) token..."
        local util="$SCRIPT_DIR/softhsm2/install/bin/softhsm2-util"
        [ -f "$util" ] || util="softhsm2-util"
        SOFTHSM2_CONF="$conf" "$util" --init-token --slot 0 \
            --label "p11test" --pin 1234 --so-pin 12345678
    fi
    export SOFTHSM2_CONF="$conf"
    MODULE="$so"; PIN="1234"
}

setup_softhsm2_system() {
    local so="/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
    [ -f "$so" ] || { echo "ERROR: System SoftHSM2 not found"; exit 1; }
    local conf="/tmp/p11test-softhsm2.conf"
    [ -f "$conf" ] || bash "$PROJECT_DIR/scripts/setup-softhsm.sh"
    export SOFTHSM2_CONF="$conf"
    MODULE="$so"; PIN="1234"
}

setup_opencryptoki() {
    local so="$SCRIPT_DIR/opencryptoki/lib/libopencryptoki.so"
    [ -f "$so" ] || { echo "ERROR: Build first: bash local-builds/build.sh opencryptoki"; exit 1; }
    echo "NOTE: OpenCryptoki needs pkcsslotd running."
    echo "  sudo $SCRIPT_DIR/opencryptoki/install/sbin/pkcsslotd"
    MODULE="$so"; PIN="1234"
}

setup_tpm2() {
    local so="$SCRIPT_DIR/tpm2-pkcs11/lib/libtpm2_pkcs11.so"
    if [ ! -f "$so" ]; then
        # Try system package
        so=$(find /usr/lib64 /usr/lib -name "libtpm2_pkcs11.so" 2>/dev/null | head -1)
    fi
    [ -f "$so" ] || { echo "ERROR: tpm2-pkcs11 not found. Build or install package."; exit 1; }
    export TPM2_PKCS11_STORE="$TOKENS_DIR/tpm2"
    mkdir -p "$TPM2_PKCS11_STORE"
    MODULE="$so"; PIN="1234"
}

setup_pkcs11_mock() {
    local so="$SCRIPT_DIR/pkcs11-mock/lib/pkcs11-mock.so"
    [ -f "$so" ] || { echo "ERROR: Build first: bash local-builds/build.sh pkcs11-mock"; exit 1; }
    MODULE="$so"; PIN=""
}

setup_qryptotoken() {
    local so="$SCRIPT_DIR/qryptotoken/lib/libqryptotoken_pkcs11.so"
    [ -f "$so" ] || { echo "ERROR: Build first: bash local-builds/build.sh qryptotoken"; exit 1; }
    MODULE="$so"; PIN="1234"
}

setup_bouncyhsm() {
    local so="$SCRIPT_DIR/bouncyhsm/lib/libbouncyhsm_pkcs11.so"
    [ -f "$so" ] || { echo "ERROR: Build first: bash local-builds/build.sh bouncyhsm"; exit 1; }
    echo "NOTE: BouncyHSM server must be running."
    echo "  dotnet $SCRIPT_DIR/bouncyhsm/server/BouncyHsm.dll"
    MODULE="$so"; PIN="1234"
}

case "$TARGET" in
    kryoptic)         setup_kryoptic ;;
    softhsm2-local)   setup_softhsm2_local ;;
    softhsm2-system|softhsm2) setup_softhsm2_system ;;
    opencryptoki)     setup_opencryptoki ;;
    tpm2|tpm2-pkcs11) setup_tpm2 ;;
    pkcs11-mock)      setup_pkcs11_mock ;;
    qryptotoken)      setup_qryptotoken ;;
    bouncyhsm)        setup_bouncyhsm ;;
    *)
        echo "Usage: $0 <target> [pytest-args...]"
        echo ""
        echo "Targets:"
        echo "  kryoptic        — locally-built Kryoptic"
        echo "  softhsm2-local  — locally-built SoftHSM2 2.7.0"
        echo "  softhsm2        — system SoftHSM2 (Ubuntu 2.6.1)"
        echo "  opencryptoki    — locally-built OpenCryptoki"
        echo "  tpm2            — tpm2-pkcs11 (local or system)"
        echo "  pkcs11-mock     — locally-built pkcs11-mock"
        echo "  qryptotoken     — locally-built qryptotoken"
        echo "  bouncyhsm       — locally-built BouncyHSM"
        echo ""
        echo "Examples:"
        echo "  $0 kryoptic                      # full suite"
        echo "  $0 kryoptic -k test_encrypt -v   # specific tests"
        echo "  $0 softhsm2-local -x --tb=short  # stop on first fail"
        exit 1
        ;;
esac

echo "=== Running p11test ==="
echo "Module: $MODULE"
echo "PIN: ${PIN:-<none>}"
echo ""

cd "$PROJECT_DIR"
PYTEST_ARGS=(src/p11test/testcases/ "--p11-module=$MODULE" "--benchmark-disable")
[ -n "${PIN:-}" ] && PYTEST_ARGS+=("--p11-pin=$PIN")
PYTEST_ARGS+=("$@")

exec uv run pytest "${PYTEST_ARGS[@]}"
