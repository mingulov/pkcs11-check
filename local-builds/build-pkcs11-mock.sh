#!/usr/bin/env bash
# Build pkcs11-mock locally.
# Usage: bash local-builds/build-pkcs11-mock.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/pkcs11-mock/src"
LIB="$SCRIPT_DIR/pkcs11-mock/lib"
mkdir -p "$LIB"

echo "=== Building pkcs11-mock ==="

if [ ! -d "$SRC" ]; then
    git clone --depth 1 https://github.com/pspacek/pkcs11-mock.git "$SRC"
fi

cd "$SRC"
mkdir -p build && cd build
cmake ..
make -j"$(nproc)"

SO=$(find . -name "*.so" | head -1)
cp "$SO" "$LIB/pkcs11-mock.so"

echo "Built: $LIB/pkcs11-mock.so"
ls -lh "$LIB/pkcs11-mock.so"
