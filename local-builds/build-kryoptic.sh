#!/usr/bin/env bash
# Build Kryoptic locally.
# Usage: bash local-builds/build-kryoptic.sh [--branch v1.5.0|main]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRANCH="${1:-v1.5.0}"
SRC="$SCRIPT_DIR/kryoptic/src"
LIB="$SCRIPT_DIR/kryoptic/lib"
mkdir -p "$LIB"

echo "=== Building Kryoptic ($BRANCH) ==="

if [ ! -d "$SRC" ]; then
    git clone --depth 1 --branch "$BRANCH" https://github.com/latchset/kryoptic.git "$SRC"
elif [ "$BRANCH" = "main" ]; then
    cd "$SRC" && git fetch origin main && git checkout main && git pull
fi

cd "$SRC"
cargo build --release
cp target/release/libkryoptic_pkcs11.so "$LIB/"

echo "Built: $LIB/libkryoptic_pkcs11.so"
ls -lh "$LIB/libkryoptic_pkcs11.so"
