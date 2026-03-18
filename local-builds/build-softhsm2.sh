#!/usr/bin/env bash
# Build SoftHSM2 locally.
# Usage: bash local-builds/build-softhsm2.sh [--branch 2.7.0|master]
#
# Dependencies (Ubuntu): apt install gcc g++ libssl-dev libsqlite3-dev
#                         automake autoconf autoconf-archive libtool pkg-config
#
# To use a custom OpenSSL build:
#   export OPENSSL_DIR=/path/to/openssl/install
#   Then pass --with-openssl=$OPENSSL_DIR to configure below.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRANCH="${1:-2.7.0}"
SRC="$SCRIPT_DIR/softhsm2/src"
PREFIX="$SCRIPT_DIR/softhsm2/install"
LIB="$SCRIPT_DIR/softhsm2/lib"
mkdir -p "$LIB"

echo "=== Building SoftHSM2 ($BRANCH) ==="

if [ ! -d "$SRC" ]; then
    git clone --depth 1 --branch "$BRANCH" https://github.com/softhsm/SoftHSMv2.git "$SRC"
elif [ "$BRANCH" = "master" ]; then
    cd "$SRC" && git fetch origin master && git checkout master && git pull
fi

cd "$SRC"

[ -f configure ] || sh autogen.sh

CONFIGURE_ARGS=(
    --prefix="$PREFIX"
    --disable-gost
)

# Custom OpenSSL support
if [ -n "${OPENSSL_DIR:-}" ]; then
    echo "Using custom OpenSSL: $OPENSSL_DIR"
    CONFIGURE_ARGS+=(
        "--with-openssl=$OPENSSL_DIR"
        "LDFLAGS=-L$OPENSSL_DIR/lib -Wl,-rpath,$OPENSSL_DIR/lib"
        "CPPFLAGS=-I$OPENSSL_DIR/include"
    )
fi

[ -f Makefile ] || ./configure "${CONFIGURE_ARGS[@]}"

make -j"$(nproc)"
make install

SO=$(find "$PREFIX" -name "libsofthsm2.so" | head -1)
cp "$SO" "$LIB/"

echo "Built: $LIB/libsofthsm2.so"
ls -lh "$LIB/libsofthsm2.so"
echo "Util: $PREFIX/bin/softhsm2-util"
