#!/usr/bin/env bash
# pkcs11-mock — minimal v3.1 PKCS#11 stub (C)
# Latest release: v2.0.0
# Requires: gcc

PROVIDER_NAME="pkcs11-mock"
DEFAULT_BRANCH="v2.0.0"
REPO="https://github.com/Pkcs11Interop/pkcs11-mock.git"

build() {
    local branch="${1:-$DEFAULT_BRANCH}"
    local src="$BASE_DIR/pkcs11-mock/src"
    local lib="$BASE_DIR/pkcs11-mock/lib"
    mkdir -p "$lib"

    echo "=== Building pkcs11-mock ($branch) ==="

    if [ ! -d "$src" ]; then
        git clone --depth 1 --branch "$branch" "$REPO" "$src"
    fi

    cd "$src/src"
    gcc -shared -fPIC -o "$lib/pkcs11-mock.so" pkcs11-mock.c -I .

    echo "Built: $lib/pkcs11-mock.so"
    ls -lh "$lib/pkcs11-mock.so"
}

setup() {
    local so="$BASE_DIR/pkcs11-mock/lib/pkcs11-mock.so"
    [ -f "$so" ] || { echo "ERROR: Build first: bash local-builds/build.sh pkcs11-mock"; exit 1; }
    MODULE="$so"
    PIN=""  # pkcs11-mock doesn't use PIN
}
