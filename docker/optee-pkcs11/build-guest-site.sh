#!/usr/bin/env bash
set -euo pipefail

site_dir="${1:-/opt/pkcs11-check-site}"
work_dir="${PKCS11_CHECK_GUEST_SITE_WORK:-/tmp/pkcs11-check-guest-site}"

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
    --python-version 3.13 \
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
