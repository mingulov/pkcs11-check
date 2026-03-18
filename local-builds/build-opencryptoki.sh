#!/usr/bin/env bash
# Build OpenCryptoki locally.
# Usage: bash local-builds/build-opencryptoki.sh [--branch v3.26.0|master]
#
# Dependencies (Ubuntu):
#   apt install gcc g++ automake autoconf libtool pkg-config
#   apt install libssl-dev libsqlite3-dev libcap-dev
#   apt install trousers-dbg libtspi-dev  # optional, for TPM support
#
# Note: OpenCryptoki needs the pkcsslotd daemon running.
# After building, start it with:
#   sudo local-builds/opencryptoki/install/sbin/pkcsslotd
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRANCH="${1:-v3.26.0}"
SRC="$SCRIPT_DIR/opencryptoki/src"
PREFIX="$SCRIPT_DIR/opencryptoki/install"
LIB="$SCRIPT_DIR/opencryptoki/lib"
mkdir -p "$LIB"

echo "=== Building OpenCryptoki ($BRANCH) ==="

if [ ! -d "$SRC" ]; then
    git clone --depth 1 --branch "$BRANCH" https://github.com/opencryptoki/opencryptoki.git "$SRC"
elif [ "$BRANCH" = "master" ]; then
    cd "$SRC" && git fetch origin master && git checkout master && git pull
fi

cd "$SRC"

[ -f configure ] || ./bootstrap.sh

CONFIGURE_ARGS=(
    --prefix="$PREFIX"
    --enable-swtok
    --disable-tpmtok
    --disable-ccatok
    --disable-ep11tok
    --disable-icatok
)

# Custom OpenSSL
if [ -n "${OPENSSL_DIR:-}" ]; then
    echo "Using custom OpenSSL: $OPENSSL_DIR"
    CONFIGURE_ARGS+=(
        "LDFLAGS=-L$OPENSSL_DIR/lib -Wl,-rpath,$OPENSSL_DIR/lib"
        "CPPFLAGS=-I$OPENSSL_DIR/include"
        "PKG_CONFIG_PATH=$OPENSSL_DIR/lib/pkgconfig"
    )
fi

[ -f Makefile ] || ./configure "${CONFIGURE_ARGS[@]}"

make -j"$(nproc)"
make install

SO=$(find "$PREFIX" -name "libopencryptoki.so" | head -1)
if [ -n "$SO" ]; then
    cp "$SO" "$LIB/"
    echo "Built: $LIB/libopencryptoki.so"
    ls -lh "$LIB/libopencryptoki.so"
else
    echo "WARNING: libopencryptoki.so not found — check build output"
    find "$PREFIX" -name "*.so" | head -10
fi

echo ""
echo "To run: sudo $PREFIX/sbin/pkcsslotd"
echo "Module: $LIB/libopencryptoki.so"
