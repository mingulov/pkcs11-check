#!/usr/bin/env bash
# Build OpenSSL locally — for use as dependency by other tokens.
# Usage: bash local-builds/build-openssl.sh [--branch openssl-3.5.0|master]
#
# After building, set OPENSSL_DIR to use with SoftHSM2, Kryoptic, etc:
#   export OPENSSL_DIR=$(pwd)/local-builds/openssl/install
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRANCH="${1:-openssl-3.5.0}"
SRC="$SCRIPT_DIR/openssl/src"
PREFIX="$SCRIPT_DIR/openssl/install"
mkdir -p "$PREFIX"

echo "=== Building OpenSSL ($BRANCH) ==="

if [ ! -d "$SRC" ]; then
    git clone --depth 1 --branch "$BRANCH" https://github.com/openssl/openssl.git "$SRC"
elif [ "$BRANCH" = "master" ]; then
    cd "$SRC" && git fetch origin master && git checkout master && git pull
fi

cd "$SRC"

if [ ! -f Makefile ]; then
    ./Configure --prefix="$PREFIX" --openssldir="$PREFIX/ssl" \
        shared no-tests
fi

make -j"$(nproc)"
make install_sw  # skip docs

echo ""
echo "Built: $PREFIX/lib/libssl.so"
ls -lh "$PREFIX/lib/libssl.so"* 2>/dev/null || ls -lh "$PREFIX/lib64/libssl.so"* 2>/dev/null
echo ""
echo "To use with other builds:"
echo "  export OPENSSL_DIR=$PREFIX"
echo "  export LD_LIBRARY_PATH=$PREFIX/lib:\$LD_LIBRARY_PATH"
