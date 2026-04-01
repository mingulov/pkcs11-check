#!/usr/bin/env bash
# Fault injection PKCS#11 proxy
# Wraps a real module and can inject specific CKR error codes.
#
# Usage:
#   bash local-builds/build.sh fault-proxy
#   PKCS11_REAL_MODULE=/usr/lib/softhsm/libsofthsm2.so \
#     PKCS11_INJECT_FUNCTION=C_Encrypt \
#     PKCS11_INJECT_ERROR=0x00000032 \
#     python -c "import pkcs11; ..."

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROXY_DIR="$SCRIPT_DIR/../fault-proxy"

build() {
    echo "Building fault-proxy..."
    gcc -shared -fPIC -o "$PROXY_DIR/fault-proxy.so" \
        "$PROXY_DIR/fault-proxy.c" -ldl
    echo "Built: $PROXY_DIR/fault-proxy.so"
}

setup() {
    if [[ ! -f "$PROXY_DIR/fault-proxy.so" ]]; then
        echo "ERROR: fault-proxy not built. Run: bash local-builds/build.sh fault-proxy"
        return 1
    fi
    export PROVIDER_NAME="fault-proxy"
    export MODULE="$PROXY_DIR/fault-proxy.so"
    echo "Fault proxy ready: $MODULE"
}
