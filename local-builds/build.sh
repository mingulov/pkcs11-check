#!/usr/bin/env bash
# Build one or all soft tokens locally.
# Usage: bash local-builds/build.sh <target> [branch] [--sanitize]
#
# Each provider is defined in local-builds/providers/<name>.sh
# --sanitize: build with AddressSanitizer (ASAN) for memory bug detection
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export BASE_DIR="$SCRIPT_DIR"
export PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
export SANITIZE=""

PROVIDERS_DIR="$SCRIPT_DIR/providers"

# Parse --sanitize flag
ARGS=()
for arg in "$@"; do
    if [ "$arg" = "--sanitize" ]; then
        export SANITIZE="1"
        export CFLAGS="${CFLAGS:-} -fsanitize=address -fno-omit-frame-pointer -g"
        export CXXFLAGS="${CXXFLAGS:-} -fsanitize=address -fno-omit-frame-pointer -g"
        export LDFLAGS="${LDFLAGS:-} -fsanitize=address"
        echo "*** ASAN enabled: AddressSanitizer build ***"
    else
        ARGS+=("$arg")
    fi
done
set -- "${ARGS[@]}"

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
            [ "$name" = "openssl" ] && continue
            _load_provider "$name"
            build "${2:-}" || echo "WARN: $name build failed"
        done
        ;;
    help|--help|-h)
        echo "Usage: $0 <target> [branch] [--sanitize]"
        echo ""
        echo "Options:"
        echo "  --sanitize    Build with AddressSanitizer (ASAN)"
        echo ""
        echo "Available providers:"
        _list_providers
        echo ""
        echo "Examples:"
        echo "  $0 openssl                     # build OpenSSL 4.0.0"
        echo "  $0 kryoptic                    # build Kryoptic v1.5.0"
        echo "  $0 softhsm2 --sanitize         # build SoftHSM2 with ASAN"
        echo "  $0 kryoptic main               # build Kryoptic dev branch"
        echo "  $0 all                         # build everything"
        ;;
    *)
        _load_provider "$1"
        build "${2:-}"
        ;;
esac
