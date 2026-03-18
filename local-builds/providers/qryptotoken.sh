#!/usr/bin/env bash
# qryptotoken — Rust PQC PKCS#11 token (QUBIP, experimental)
# Latest release: v0.4.1
# Requires: rustc 1.70+

PROVIDER_NAME="qryptotoken"
DEFAULT_BRANCH="v0.4.1"
REPO="https://github.com/QUBIP/qryptotoken.git"

build() {
    local branch="${1:-$DEFAULT_BRANCH}"
    local src="$BASE_DIR/qryptotoken/src"
    local lib="$BASE_DIR/qryptotoken/lib"
    mkdir -p "$lib"

    echo "=== Building qryptotoken ($branch) ==="

    if [ ! -d "$src" ]; then
        git clone --depth 1 --branch "$branch" "$REPO" "$src"
    elif [ "$branch" = "main" ]; then
        cd "$src" && git fetch origin main && git checkout main && git pull
    fi

    cd "$src"
    cargo build --release

    local so=$(find target/release -name "*.so" -not -name "*.d" | head -1)
    [ -n "$so" ] && cp "$so" "$lib/libqryptotoken_pkcs11.so"

    echo "Built: $lib/libqryptotoken_pkcs11.so"
    ls -lh "$lib/libqryptotoken_pkcs11.so"
}

setup() {
    local so="$BASE_DIR/qryptotoken/lib/libqryptotoken_pkcs11.so"
    [ -f "$so" ] || { echo "ERROR: Build first: bash local-builds/build.sh qryptotoken"; exit 1; }
    MODULE="$so"
    PIN="1234"
}
