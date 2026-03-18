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
    git clone --depth 1 --branch v2.0.0 https://github.com/Pkcs11Interop/pkcs11-mock.git "$SRC"
fi

cd "$SRC/src"
gcc -shared -fPIC -o "$LIB/pkcs11-mock.so" pkcs11-mock.c -I .
echo "Built: $LIB/pkcs11-mock.so"
ls -lh "$LIB/pkcs11-mock.so"
