#!/usr/bin/env bash
# tpm2-pkcs11 — TPM 2.0 based PKCS#11 token
# Latest release: 1.9.2 (system package: 1.9.0)
# Requires: libtss2-dev, tpm2-tools
# Hardware TPM at /dev/tpm0 preferred; swtpm as fallback.

PROVIDER_NAME="tpm2-pkcs11"
DEFAULT_BRANCH="1.9.2"
REPO="https://github.com/tpm2-software/tpm2-pkcs11.git"

build() {
    local branch="${1:-$DEFAULT_BRANCH}"
    local lib="$BASE_DIR/tpm2-pkcs11/lib"
    mkdir -p "$lib"

    echo "=== tpm2-pkcs11 ==="

    # Prefer system package (building from source needs many Python deps)
    local system_so=$(find /usr/lib64 /usr/lib -name "libtpm2_pkcs11.so" -not -type l 2>/dev/null | head -1)
    if [ -n "$system_so" ]; then
        echo "Using system package: $system_so"
        ln -sf "$system_so" "$lib/libtpm2_pkcs11.so"
        ls -lh "$lib/libtpm2_pkcs11.so"
        return
    fi

    echo "System package not found. Install: apt install libtpm2-pkcs11-1"
    echo "Building from source requires many Python deps — use Docker for full build."
    exit 1
}

setup() {
    local so="$BASE_DIR/tpm2-pkcs11/lib/libtpm2_pkcs11.so"
    if [ ! -f "$so" ] && [ ! -L "$so" ]; then
        so=$(find /usr/lib64 /usr/lib -name "libtpm2_pkcs11.so" 2>/dev/null | head -1)
    fi
    [ -f "$so" ] || [ -L "$so" ] || { echo "ERROR: tpm2-pkcs11 not found."; exit 1; }

    # Check for hardware TPM
    if [ -c /dev/tpm0 ] || [ -c /dev/tpmrm0 ]; then
        echo "Hardware TPM detected"
    else
        echo "WARNING: No hardware TPM — need swtpm running"
    fi

    export TPM2_PKCS11_STORE="$TOKENS_DIR/tpm2"
    mkdir -p "$TPM2_PKCS11_STORE"
    MODULE="$so"
    PIN="1234"
}
