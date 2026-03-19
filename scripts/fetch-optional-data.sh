#!/usr/bin/env bash
# Fetch optional large test vector submodules.
#
# These are NOT in .gitmodules to prevent accidental download with
# git clone --recurse-submodules (ACVP=1.1GB, x509-limbo=194MB).
#
# Usage:
#   bash scripts/fetch-optional-data.sh acvp
#   bash scripts/fetch-optional-data.sh x509-limbo
#   bash scripts/fetch-optional-data.sh all

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

DATA_DIR="src/p11test/testcases/data"

fetch_acvp() {
    if [ -d "$DATA_DIR/acvp/.git" ]; then
        echo "ACVP already cloned at $DATA_DIR/acvp"
        return
    fi
    echo "Cloning NIST ACVP-Server (shallow, ~1.1GB)..."
    git submodule add --depth 1 \
        https://github.com/usnistgov/ACVP-Server.git \
        "$DATA_DIR/acvp"
    echo "Done. ACVP vectors at: $DATA_DIR/acvp/json-files/"
}

fetch_x509_limbo() {
    if [ -d "$DATA_DIR/x509-limbo/.git" ]; then
        echo "x509-limbo already cloned at $DATA_DIR/x509-limbo"
        return
    fi
    echo "Cloning C2SP/x509-limbo (shallow, ~194MB)..."
    git submodule add --depth 1 \
        https://github.com/C2SP/x509-limbo.git \
        "$DATA_DIR/x509-limbo"
    echo "Done. Certificates at: $DATA_DIR/x509-limbo/"
}

case "${1:-help}" in
    acvp)
        fetch_acvp
        ;;
    x509-limbo|x509|limbo)
        fetch_x509_limbo
        ;;
    all)
        fetch_acvp
        fetch_x509_limbo
        ;;
    *)
        echo "Usage: $0 {acvp|x509-limbo|all}"
        echo ""
        echo "Optional test vector sources (large, not cloned by default):"
        echo "  acvp        — NIST ACVP-Server (~1.1GB): SLH-DSA, LMS, DRBG, PQC"
        echo "  x509-limbo  — C2SP/x509-limbo (~194MB): 7000+ pathological X.509 certs"
        exit 1
        ;;
esac
