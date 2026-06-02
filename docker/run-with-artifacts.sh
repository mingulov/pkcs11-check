#!/usr/bin/env bash
set -euo pipefail

artifact_dir="${PKCS11_CHECK_ARTIFACT_DIR:-}"
artifact_owner="${PKCS11_CHECK_ARTIFACT_OWNER:-}"

if [[ -z "$artifact_dir" ]]; then
    exec "$@"
fi

mkdir -p "$artifact_dir"
log_file="${PKCS11_CHECK_CONSOLE_LOG:-$artifact_dir/console.log}"

if [[ -z "$artifact_owner" && -d /artifacts ]]; then
    artifact_owner="$(stat -c '%u:%g' /artifacts 2>/dev/null || true)"
fi

finish_artifacts() {
    local rc=$?
    if [[ -n "$artifact_owner" && -d "$artifact_dir" ]]; then
        chown -R "$artifact_owner" "$artifact_dir" 2>/dev/null || true
    fi
    exit "$rc"
}
trap finish_artifacts EXIT

set +e
"$@" 2>&1 | tee "$log_file"
rc=${PIPESTATUS[0]}
set -e

exit "$rc"
