#!/usr/bin/env bash
set -euo pipefail

artifact_dir="${PKCS11_CHECK_ARTIFACT_DIR:-}"

if [[ -z "$artifact_dir" ]]; then
    exec "$@"
fi

mkdir -p "$artifact_dir"
log_file="${PKCS11_CHECK_CONSOLE_LOG:-$artifact_dir/console.log}"

set +e
"$@" 2>&1 | tee "$log_file"
rc=${PIPESTATUS[0]}
set -e

exit "$rc"
