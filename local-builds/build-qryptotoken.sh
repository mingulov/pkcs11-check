#!/usr/bin/env bash
# Build qryptotoken (Rust PQC token) locally.
# Usage: bash local-builds/build-qryptotoken.sh [--branch main]
#
# qryptotoken is an experimental PQC-capable PKCS#11 token from QUBIP.
# Requires Rust toolchain.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRANCH="${1:-main}"
SRC="$SCRIPT_DIR/qryptotoken/src"
LIB="$SCRIPT_DIR/qryptotoken/lib"
mkdir -p "$LIB"

echo "=== Building qryptotoken ($BRANCH) ==="

if [ ! -d "$SRC" ]; then
    git clone --depth 1 --branch "$BRANCH" https://github.com/QUBIP/qryptotoken.git "$SRC"
elif [ "$BRANCH" = "main" ]; then
    cd "$SRC" && git fetch origin main && git checkout main && git pull
fi

cd "$SRC"
cargo build --release 2>&1

# qryptotoken produces a cdylib .so
SO=$(find target/release -name "*.so" -not -name "*.d" | head -1)
if [ -n "$SO" ]; then
    cp "$SO" "$LIB/libqryptotoken_pkcs11.so"
    echo "Built: $LIB/libqryptotoken_pkcs11.so"
    ls -lh "$LIB/libqryptotoken_pkcs11.so"
else
    echo "WARNING: .so not found — check build output"
    find target/release -name "*.so" | head -10
fi
