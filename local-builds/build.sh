#!/usr/bin/env bash
# Build one or all soft tokens locally.
# Usage: bash local-builds/build.sh [kryoptic|softhsm2|pkcs11-mock|all]
#
# For per-token options (branch, custom OpenSSL, etc.),
# use the individual build-<token>.sh scripts directly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "${1:-all}" in
    kryoptic)    bash "$SCRIPT_DIR/build-kryoptic.sh" ;;
    softhsm2)    bash "$SCRIPT_DIR/build-softhsm2.sh" ;;
    pkcs11-mock) bash "$SCRIPT_DIR/build-pkcs11-mock.sh" ;;
    all)
        bash "$SCRIPT_DIR/build-kryoptic.sh"
        bash "$SCRIPT_DIR/build-softhsm2.sh"
        bash "$SCRIPT_DIR/build-pkcs11-mock.sh"
        ;;
    *)
        echo "Usage: $0 [kryoptic|softhsm2|pkcs11-mock|all]"
        echo ""
        echo "Or use individual scripts:"
        echo "  bash local-builds/build-kryoptic.sh [--branch main]"
        echo "  bash local-builds/build-softhsm2.sh [--branch master]"
        echo "  bash local-builds/build-pkcs11-mock.sh"
        exit 1
        ;;
esac
