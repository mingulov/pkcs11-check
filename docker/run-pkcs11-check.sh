#!/usr/bin/env bash
set -euo pipefail

# Default data dir for Docker containers (host data/ mounted at /app/data)
export PKCS11_CHECK_DATA_DIR="${PKCS11_CHECK_DATA_DIR:-/app/data}"

module="${PKCS11_CHECK_MODULE:-${P11TEST_MODULE:-}}"
pin="${PKCS11_CHECK_PIN:-${P11TEST_PIN:-}}"
slot="${PKCS11_CHECK_SLOT:-}"
interface="${PKCS11_CHECK_INTERFACE:-}"
isolation="${PKCS11_CHECK_ISOLATION:-auto}"
timeout="${PKCS11_CHECK_TIMEOUT:-}"
category="${PKCS11_CHECK_CATEGORY:-}"
match="${PKCS11_CHECK_MATCH:-}"
marker="${PKCS11_CHECK_MARKER:-}"
max_crashes_per_file="${PKCS11_CHECK_MAX_CRASHES_PER_FILE:-}"
artifact_dir="${PKCS11_CHECK_ARTIFACT_DIR:-}"
targets_env="${PKCS11_CHECK_TARGETS:-}"
extra_args_env="${PKCS11_CHECK_EXTRA_ARGS:-}"
python_bin="${PKCS11_CHECK_PYTHON:-}"

shlex_split_into() {
    local value="$1"
    local -n destination="$2"

    if [[ -z "$value" ]]; then
        return
    fi

    while IFS= read -r -d '' item; do
        destination+=("$item")
    done < <(
        VALUE="$value" python3 -c \
            'import os, shlex, sys; [sys.stdout.write(part + "\0") for part in shlex.split(os.environ.get("VALUE", ""))]'
    )
}

if [[ -z "$module" ]]; then
    echo "PKCS11_CHECK_MODULE or P11TEST_MODULE must be set" >&2
    exit 2
fi

if [[ -z "$python_bin" ]]; then
    python_bin="$(command -v python3 || true)"
fi

# Skip re-syncing at runtime — deps were installed during Docker build.
# Without --no-sync, uv rebuilds the venv on every container start (~5-10s).
args=(uv run --no-sync)
if [[ -n "$python_bin" ]]; then
    args+=(--python "$python_bin")
fi
args+=(
    pkcs11-check test
    --module "$module"
    --isolation "$isolation"
)

if [[ -n "$pin" ]]; then
    args+=(--pin "$pin")
fi

if [[ -n "$slot" ]]; then
    args+=(--slot "$slot")
fi

if [[ -n "$interface" ]]; then
    args+=(--interface "$interface")
fi

if [[ -n "$timeout" ]]; then
    args+=(--timeout "$timeout")
fi

if [[ -n "$category" ]]; then
    args+=(--category "$category")
fi

if [[ -n "$match" ]]; then
    args+=(--match "$match")
fi

if [[ -n "$marker" ]]; then
    args+=(--marker "$marker")
fi

if [[ -n "$max_crashes_per_file" ]]; then
    args+=(--max-crashes-per-file "$max_crashes_per_file")
fi

if [[ "${PKCS11_CHECK_DESTRUCTIVE:-0}" != "0" ]]; then
    args+=(--destructive)
fi

if [[ -n "$artifact_dir" ]]; then
    mkdir -p "$artifact_dir"
    args+=(
        --output json
        --output-file "$artifact_dir/results.json"
        --state-file "$artifact_dir/state.json"
        --policy-file "$artifact_dir/policy.json"
    )
fi

extra_args=()
shlex_split_into "$extra_args_env" extra_args
if [[ "${#extra_args[@]}" -gt 0 ]]; then
    args+=("${extra_args[@]}")
fi

target_args=()
shlex_split_into "$targets_env" target_args

if [[ "$#" -gt 0 ]]; then
    args+=("$@")
elif [[ "${#target_args[@]}" -gt 0 ]]; then
    args+=("${target_args[@]}")
else
    args+=(src/pkcs11_check/testcases/)
fi

exec "${args[@]}"
