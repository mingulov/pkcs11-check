#!/usr/bin/env bash
# Build Kryoptic locally.
# Usage: bash local-builds/build-kryoptic.sh [--branch v1.5.0|main]
#
# Kryoptic requires OpenSSL 3.2+. If the system OpenSSL is older,
# build a local one first:
#   bash local-builds/build-openssl.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRANCH="${1:-v1.5.0}"
SRC="$SCRIPT_DIR/kryoptic/src"
LIB="$SCRIPT_DIR/kryoptic/lib"
mkdir -p "$LIB"

echo "=== Building Kryoptic ($BRANCH) ==="

# Auto-detect local OpenSSL build if system version is too old
SYSTEM_OSSL_VER=$(openssl version 2>/dev/null | awk '{print $2}' | cut -d. -f1,2)
LOCAL_OSSL="$SCRIPT_DIR/openssl/install"
if [ -d "$LOCAL_OSSL" ] && [ -z "${OPENSSL_DIR:-}" ]; then
    echo "Using local OpenSSL build: $LOCAL_OSSL"
    export OPENSSL_DIR="$LOCAL_OSSL"
    export PKG_CONFIG_PATH="$LOCAL_OSSL/lib64/pkgconfig:$LOCAL_OSSL/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
    export LD_LIBRARY_PATH="$LOCAL_OSSL/lib64:$LOCAL_OSSL/lib:${LD_LIBRARY_PATH:-}"
elif [ "${SYSTEM_OSSL_VER}" \< "3.2" ] && [ -z "${OPENSSL_DIR:-}" ]; then
    echo "System OpenSSL $SYSTEM_OSSL_VER is too old (need 3.2+)."
    echo "Build local OpenSSL first: bash local-builds/build-openssl.sh"
    exit 1
fi

if [ ! -d "$SRC" ]; then
    git clone --depth 1 --branch "$BRANCH" https://github.com/latchset/kryoptic.git "$SRC"
elif [ "$BRANCH" = "main" ]; then
    cd "$SRC" && git fetch origin main && git checkout main && git pull
fi

cd "$SRC"

# Enable all features: standard crypto + PQC (ML-KEM, ML-DSA, SLH-DSA) + profiles
# PQC requires OpenSSL 3.5+ (ossl350 feature)
FEATURES="standard,pqc,profiles,aes,log"
echo "Features: $FEATURES"
cargo build --release --features "$FEATURES"
cp target/release/libkryoptic_pkcs11.so "$LIB/"

echo "Built: $LIB/libkryoptic_pkcs11.so"
ls -lh "$LIB/libkryoptic_pkcs11.so"
