#!/usr/bin/env bash
# Build tpm2-pkcs11 locally with swtpm (software TPM).
# Usage: bash local-builds/build-tpm2-pkcs11.sh [--branch master]
#
# Dependencies (Ubuntu):
#   apt install swtpm swtpm-tools tpm2-tools tpm2-abrmd
#   apt install libtss2-dev libtpm2-pkcs11-1-dev  # or build from source
#   apt install libsqlite3-dev libyaml-dev libssl-dev autoconf-archive
#
# This builds tpm2-pkcs11 from source. For the software TPM stack:
#   swtpm + tpm2-abrmd are used from system packages.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRANCH="${1:-master}"
SRC="$SCRIPT_DIR/tpm2-pkcs11/src"
PREFIX="$SCRIPT_DIR/tpm2-pkcs11/install"
LIB="$SCRIPT_DIR/tpm2-pkcs11/lib"
mkdir -p "$LIB"

echo "=== Building tpm2-pkcs11 ($BRANCH) ==="

# Check dependencies
for dep in swtpm tpm2_ptool; do
    if ! command -v "$dep" &>/dev/null; then
        echo "WARNING: $dep not found — install swtpm and tpm2-tools packages"
    fi
done

if [ ! -d "$SRC" ]; then
    git clone --depth 1 --branch "$BRANCH" https://github.com/tpm2-software/tpm2-pkcs11.git "$SRC"
elif [ "$BRANCH" = "master" ]; then
    cd "$SRC" && git fetch origin master && git checkout master && git pull
fi

cd "$SRC"

[ -f configure ] || ./bootstrap

CONFIGURE_ARGS=(
    --prefix="$PREFIX"
)

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
echo "To initialize swtpm + token, see local-builds/test.sh tpm2"
