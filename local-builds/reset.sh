#!/usr/bin/env bash
# Reset token data for one or all providers.
# Usage: bash local-builds/reset.sh [target|all]
#
# This deletes token databases/stores so tokens can be re-initialized.
# Does NOT delete source code or built .so files.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOKENS_DIR="$SCRIPT_DIR/tokens"

reset_one() {
    local name="$1"
    local dir="$TOKENS_DIR/$name"
    if [ -d "$dir" ]; then
        rm -rf "$dir"
        echo "Reset: $name (deleted $dir)"
    else
        echo "Skip: $name (no data at $dir)"
    fi
}

case "${1:-help}" in
    all)
        rm -rf "$TOKENS_DIR"
        mkdir -p "$TOKENS_DIR"
        echo "Reset all token data in $TOKENS_DIR"
        ;;
    help|--help)
        echo "Usage: $0 [target|all]"
        echo ""
        echo "Targets: kryoptic softhsm2 opencryptoki tpm2 pkcs11-mock qryptotoken bouncyhsm"
        echo ""
        echo "Examples:"
        echo "  $0 kryoptic   # reset Kryoptic token only"
        echo "  $0 all        # reset all tokens"
        ;;
    *)
        reset_one "$1"
        ;;
esac
