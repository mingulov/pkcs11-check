#!/usr/bin/env bash
# Run p11test against a locally-built soft token.
# Usage: bash local-builds/test.sh <target> [pytest-args...]
#
# Each provider is defined in local-builds/providers/<name>.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export BASE_DIR="$SCRIPT_DIR"
export PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
export TOKENS_DIR="$SCRIPT_DIR/tokens"
mkdir -p "$TOKENS_DIR"

PROVIDERS_DIR="$SCRIPT_DIR/providers"

TARGET="${1:-}"
shift 2>/dev/null || true

_load_provider() {
    local name="$1"
    local provider_file="$PROVIDERS_DIR/$name.sh"
    [ -f "$provider_file" ] || { echo "ERROR: Unknown provider '$name'. Available:"; _list_providers; exit 1; }
    source "$provider_file"
}

_list_providers() {
    for f in "$PROVIDERS_DIR"/*.sh; do
        local name=$(basename "$f" .sh)
        [ "$name" = "openssl" ] && continue  # not a PKCS#11 provider
        local desc=$(grep "^#.*—" "$f" | head -1 | sed 's/^# *//')
        printf "  %-16s %s\n" "$name" "$desc"
    done
}

# Handle aliases and variants
SETUP_FUNC="setup"
case "$TARGET" in
    softhsm2-system)
        TARGET="softhsm2"
        SETUP_FUNC="setup_system"
        ;;
    softhsm2-local)
        TARGET="softhsm2"
        ;;
    tpm2)
        TARGET="tpm2-pkcs11"
        ;;
esac

if [ -z "$TARGET" ] || [ "$TARGET" = "help" ] || [ "$TARGET" = "--help" ]; then
    echo "Usage: $0 <target> [pytest-args...]"
    echo ""
    echo "Available providers:"
    _list_providers
    echo "  softhsm2-local  — locally-built SoftHSM2"
    echo "  softhsm2-system — system SoftHSM2 (Ubuntu package)"
    echo ""
    echo "Examples:"
    echo "  $0 kryoptic                      # full suite"
    echo "  $0 kryoptic -k test_encrypt -v   # specific tests"
    echo "  $0 softhsm2-local -x --tb=short  # stop on first fail"
    echo "  P11TEST_ISOLATION=file $0 bouncyhsm src/p11test/testcases/ckr/test_ckr_codes.py"
    exit 1
fi

_load_provider "$TARGET"
$SETUP_FUNC

echo "=== Running p11test ==="
echo "Provider: $PROVIDER_NAME"
echo "Module:   $MODULE"
echo "PIN:      ${PIN:-<none>}"
echo ""

cd "$PROJECT_DIR"

# Export provider-specific environment variables (e.g., NSS_LIB_PARAMS)
if type -t get_env &>/dev/null; then
    while IFS= read -r envline; do
        if [ -n "$envline" ]; then
            env_name="${envline%%=*}"
            if [ -z "${!env_name+x}" ]; then
                export "$envline"
            fi
        fi
    done < <(get_env)
fi

# Provider may specify a slot
local_slot=""
if type -t get_slot &>/dev/null; then
    local_slot="$(get_slot)"
fi

use_isolation_runner=0
if [ "${P11TEST_ISOLATION:-none}" != "none" ]; then
    use_isolation_runner=1
fi
for arg in "$@"; do
    case "$arg" in
        --isolation|--isolation=*|--resume|--stop-on-failure|--state-file|--state-file=*)
            use_isolation_runner=1
            ;;
    esac
done

if [ "$use_isolation_runner" -eq 1 ]; then
    isolation_mode="${P11TEST_ISOLATION:-none}"
    resume="${P11TEST_RESUME:-0}"
    stop_on_failure="${P11TEST_STOP_ON_FAILURE:-0}"
    state_file="${P11TEST_STATE_FILE:-}"
    match=""
    verbose=0
    destructive=0
    targets=()

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --isolation)
                isolation_mode="${2:-}"
                shift 2
                ;;
            --isolation=*)
                isolation_mode="${1#*=}"
                shift
                ;;
            --resume)
                resume=1
                shift
                ;;
            --stop-on-failure|-x)
                stop_on_failure=1
                shift
                ;;
            --state-file)
                state_file="${2:-}"
                shift 2
                ;;
            --state-file=*)
                state_file="${1#*=}"
                shift
                ;;
            -k|--match)
                match="${2:-}"
                shift 2
                ;;
            --match=*)
                match="${1#*=}"
                shift
                ;;
            -v|--verbose)
                verbose=1
                shift
                ;;
            -q|--benchmark-disable)
                shift
                ;;
            --destructive)
                destructive=1
                shift
                ;;
            --)
                shift
                while [ "$#" -gt 0 ]; do
                    targets+=("$1")
                    shift
                done
                ;;
            -*)
                echo "ERROR: unsupported argument in isolation mode: $1" >&2
                echo "Use 'uv run p11test test ...' for arbitrary pytest flags." >&2
                exit 2
                ;;
            *)
                targets+=("$1")
                shift
                ;;
        esac
    done

    CLI_ARGS=(test --module "$MODULE" --isolation "$isolation_mode")
    [ -n "${PIN:-}" ] && CLI_ARGS+=("--pin" "$PIN")
    [ -n "${local_slot:-}" ] && CLI_ARGS+=("--slot" "$local_slot")
    [ "$resume" != "0" ] && CLI_ARGS+=("--resume")
    [ "$stop_on_failure" != "0" ] && CLI_ARGS+=("--stop-on-failure")
    [ -n "$state_file" ] && CLI_ARGS+=("--state-file" "$state_file")
    [ "$verbose" != "0" ] && CLI_ARGS+=("--verbose")
    [ "$destructive" != "0" ] && CLI_ARGS+=("--destructive")
    [ -n "$match" ] && CLI_ARGS+=("--match" "$match")
    [ "${#targets[@]}" -gt 0 ] && CLI_ARGS+=("${targets[@]}")

    exec uv run p11test "${CLI_ARGS[@]}"
fi

value_option=""
targets=()
passthrough_args=()
for arg in "$@"; do
    if [ "$value_option" = "--" ]; then
        targets+=("$arg")
        continue
    fi

    if [ -n "$value_option" ]; then
        passthrough_args+=("$arg")
        value_option=""
        continue
    fi

    case "$arg" in
        -k|-m|-o|-c|--maxfail|--tb|--durations|--rootdir|--p11-slot|--timeout|--log-level|--override-ini|--benchmark-group-by|--benchmark-sort)
            passthrough_args+=("$arg")
            value_option="$arg"
            continue
            ;;
        --)
            value_option="--"
            continue
            ;;
    esac

    if [[ "$arg" == *"::"* ]] || [ -e "$arg" ]; then
        targets+=("$arg")
        continue
    fi

    passthrough_args+=("$arg")
done

if [ "${#targets[@]}" -eq 0 ]; then
    targets=(src/p11test/testcases/)
fi

PYTEST_ARGS=("${targets[@]}" "--p11-module=$MODULE" "--benchmark-disable")
[ -n "${PIN:-}" ] && PYTEST_ARGS+=("--p11-pin=$PIN")
[ -n "${local_slot:-}" ] && PYTEST_ARGS+=("--p11-slot=$local_slot")
PYTEST_ARGS+=("${passthrough_args[@]}")

exec uv run pytest "${PYTEST_ARGS[@]}"
