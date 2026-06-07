#!/usr/bin/env bash
set -euo pipefail

site_dir="${1:-/opt/pkcs11-check-site}"
work_dir="${PKCS11_CHECK_GUEST_SITE_WORK:-/tmp/pkcs11-check-guest-site}"
optee_target_dir="${PKCS11_CHECK_OPTEE_TARGET_DIR:-/optee/out-br/target}"

detect_guest_python_version() {
    if [[ -n "${PKCS11_CHECK_GUEST_PYTHON_VERSION:-}" ]]; then
        printf '%s\n' "$PKCS11_CHECK_GUEST_PYTHON_VERSION"
        return
    fi

    local python_bin="$optee_target_dir/usr/bin/python3"
    local python_name
    if [[ -e "$python_bin" ]]; then
        python_name="$(basename "$(readlink "$python_bin" || printf '%s\n' "$python_bin")")"
        if [[ "$python_name" =~ ^python([0-9]+)\.([0-9]+)$ ]]; then
            printf '%s.%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
            return
        fi
    fi

    local candidate
    for candidate in "$optee_target_dir"/usr/bin/python3.[0-9]*; do
        [[ -e "$candidate" ]] || continue
        python_name="$(basename "$candidate")"
        if [[ "$python_name" =~ ^python([0-9]+)\.([0-9]+)$ ]]; then
            printf '%s.%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
            return
        fi
    done

    echo "unable to determine OP-TEE guest Python version in $optee_target_dir" >&2
    exit 1
}

guest_python_version="$(detect_guest_python_version)"
guest_python_tag="${guest_python_version/./}"
guest_cpython_abi="cpython-${guest_python_tag}"

rm -rf "$site_dir" "$work_dir"
mkdir -p "$site_dir" "$work_dir"

uv build --wheel --out-dir "$work_dir/dist"
uv export \
    --frozen \
    --no-dev \
    --no-emit-project \
    --format requirements.txt \
    --no-hashes \
    --output-file "$work_dir/requirements.txt"

uv pip install \
    --target "$site_dir" \
    --python-version "$guest_python_version" \
    --python-platform aarch64-manylinux2014 \
    --only-binary :all: \
    --requirements "$work_dir/requirements.txt" \
    "$work_dir"/dist/*.whl

find "$site_dir" -type f -name '*.so' -print0 |
    xargs -0 -r file |
    tee "$work_dir/native-files.txt"

if grep -v 'aarch64' "$work_dir/native-files.txt" | grep -q '\.so'; then
    echo "non-aarch64 native extension found in guest site" >&2
    exit 1
fi

if grep -E '\.cpython-[0-9]+' "$work_dir/native-files.txt" |
    grep -v "$guest_cpython_abi" >&2; then
    echo "native extension for different CPython ABI found in guest site" >&2
    exit 1
fi
