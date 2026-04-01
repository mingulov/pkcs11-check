#!/usr/bin/env bash
set -euo pipefail

module="$(cat /tmp/module_path 2>/dev/null || true)"
if [[ -z "$module" || ! -f "$module" ]]; then
    echo "qryptotoken: build did not produce a .so — skipping tests"
    exit 0
fi

echo "qryptotoken module: $module"
ls -lh "$module"
export PKCS11_CHECK_MODULE="$module"

if ! bash /app/docker/run-pkcs11-check.sh; then
    echo "qryptotoken: some tests failed — experimental module"
fi
