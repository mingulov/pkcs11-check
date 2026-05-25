#!/usr/bin/env bash
set -euo pipefail

module="$(cat /tmp/module_path 2>/dev/null || true)"
if [[ -z "$module" || ! -f "$module" ]]; then
    echo "qryptotoken: build did not produce a .so — skipping tests"
    artifact_dir="${PKCS11_CHECK_ARTIFACT_DIR:-}"
    if [[ -n "$artifact_dir" ]]; then
        mkdir -p "$artifact_dir"
        revision="$(cat /tmp/qryptotoken_revision 2>/dev/null || true)"
        build_error="$(cat /tmp/qryptotoken_build_failed 2>/dev/null || true)"
        cp /tmp/qryptotoken_build.log "$artifact_dir/build.log" 2>/dev/null || true
        cat >"$artifact_dir/build-status.json" <<EOF
{
  "target": "qryptotoken",
  "status": "build_failed",
  "revision": "$revision",
  "detail": "$build_error"
}
EOF
    fi
    exit 1
fi

echo "qryptotoken module: $module"
ls -lh "$module"
export PKCS11_CHECK_MODULE="$module"

if ! bash /app/docker/run-pkcs11-check.sh; then
    echo "qryptotoken: some tests failed — experimental module"
fi
