#!/usr/bin/env bash
# Build tpm2-pkcs11 locally.
# Usage: bash local-builds/build-tpm2-pkcs11.sh [--branch 1.9.2]
#
# This system has a hardware TPM at /dev/tpm0 — no swtpm needed!
#
# Dependencies (Ubuntu):
#   apt install libtss2-dev tpm2-tools tpm2-abrmd python3-tpm2-pytss
#   apt install libsqlite3-dev libyaml-dev libssl-dev autoconf-archive
#   apt install python3-pip  # for tpm2_ptool
#   pip install tpm2-pytss tpm2-pkcs11-tools
#
# After building:
#   export TPM2_PKCS11_STORE=/path/to/store
#   tpm2_ptool init
#   tpm2_ptool addtoken --pid=1 --label=p11test --sopin=12345678 --userpin=1234
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRANCH="${1:-1.9.2}"
SRC="$SCRIPT_DIR/tpm2-pkcs11/src"
PREFIX="$SCRIPT_DIR/tpm2-pkcs11/install"
LIB="$SCRIPT_DIR/tpm2-pkcs11/lib"
mkdir -p "$LIB"

echo "=== Building tpm2-pkcs11 ($BRANCH) ==="

# Check for hardware TPM
if [ -c /dev/tpm0 ] || [ -c /dev/tpmrm0 ]; then
    echo "Hardware TPM detected at /dev/tpm0 — will use it (no swtpm needed)"
else
    echo "No hardware TPM — will need swtpm for testing"
    if ! command -v swtpm &>/dev/null; then
        echo "WARNING: Neither hardware TPM nor swtpm found"
    fi
fi

# Check build dependencies
for dep in pkg-config autoconf automake libtool; do
    command -v "$dep" &>/dev/null || { echo "ERROR: $dep not found"; exit 1; }
done

# Check for tss2 headers
if ! pkg-config --exists tss2-esys 2>/dev/null; then
    echo "ERROR: libtss2-dev not installed. Run: apt install libtss2-dev"
    exit 1
fi

if [ ! -d "$SRC" ]; then
    git clone --depth 1 --branch "$BRANCH" https://github.com/tpm2-software/tpm2-pkcs11.git "$SRC"
fi

cd "$SRC"
[ -f configure ] || ./bootstrap

CONFIGURE_ARGS=(--prefix="$PREFIX")
[ -f Makefile ] || ./configure "${CONFIGURE_ARGS[@]}"

make -j"$(nproc)"
make install

SO=$(find "$PREFIX" -name "libtpm2_pkcs11.so" | head -1)
if [ -n "$SO" ]; then
    cp "$SO" "$LIB/"
    echo "Built: $LIB/libtpm2_pkcs11.so"
    ls -lh "$LIB/libtpm2_pkcs11.so"
else
    echo "WARNING: libtpm2_pkcs11.so not found"
    find "$PREFIX" -name "*.so" | head -10
fi

echo ""
echo "To initialize token (hardware TPM):"
echo "  export TPM2_PKCS11_STORE=$SCRIPT_DIR/tokens/tpm2"
echo "  mkdir -p \$TPM2_PKCS11_STORE"
echo "  tpm2_ptool init"
echo "  tpm2_ptool addtoken --pid=1 --label=p11test --sopin=12345678 --userpin=1234"
