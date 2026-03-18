#!/usr/bin/env bash
# Build one or all soft tokens locally.
# Usage: bash local-builds/build.sh <target> [branch]
#
# Each provider is defined in local-builds/providers/<name>.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export BASE_DIR="$SCRIPT_DIR"
export PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PROVIDERS_DIR="$SCRIPT_DIR/providers"

_load_provider() {
    local name="$1"
    local provider_file="$PROVIDERS_DIR/$name.sh"
    [ -f "$provider_file" ] || { echo "ERROR: Unknown provider '$name'. Available:"; _list_providers; exit 1; }
    source "$provider_file"
}

_list_providers() {
    for f in "$PROVIDERS_DIR"/*.sh; do
        local name=$(basename "$f" .sh)
        local desc=$(grep "^#.*—" "$f" | head -1 | sed 's/^# *//')
        printf "  %-16s %s\n" "$name" "$desc"
    done
}

case "${1:-help}" in
    all)
        for f in "$PROVIDERS_DIR"/*.sh; do
            name=$(basename "$f" .sh)
            [ "$name" = "openssl" ] && continue  # build OpenSSL first
            _load_provider "$name"
            build "${2:-}" || echo "WARN: $name build failed"
        done
        ;;
    help|--help|-h)
        echo "Usage: $0 <target> [branch]"
        echo ""
        echo "Available providers:"
        _list_providers
        echo ""
        echo "Examples:"
        echo "  $0 openssl                  # build OpenSSL 3.6.1"
        echo "  $0 kryoptic                 # build Kryoptic v1.5.0"
        echo "  $0 kryoptic main            # build Kryoptic dev branch"
        echo "  $0 softhsm2 master          # build SoftHSM2 dev branch"
        echo "  $0 all                      # build everything"
        ;;
    *)
        _load_provider "$1"
        build "${2:-}"
        ;;
esac
