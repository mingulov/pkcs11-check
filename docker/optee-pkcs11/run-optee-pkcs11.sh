#!/usr/bin/env bash
set -euo pipefail

artifact_dir="${PKCS11_CHECK_ARTIFACT_DIR:-/artifacts/optee-pkcs11}"
share_dir="${PKCS11_CHECK_OPTEE_SHARE_DIR:-/tmp/optee-pkcs11-share}"
secure_dir="${PKCS11_CHECK_OPTEE_SECURE_DIR:-/tmp/optee-pkcs11-secure}"
site_dir="${PKCS11_CHECK_GUEST_SITE_DIR:-/opt/pkcs11-check-site}"

rm -rf "$share_dir" "$secure_dir"
mkdir -p "$artifact_dir" "$share_dir/artifacts" "$secure_dir"

cp -a "$site_dir" "$share_dir/site"
cp /app/docker/optee-pkcs11/guest-runner.py "$share_dir/guest-runner.py"

python3 - <<'PY' > "$share_dir/runner.env"
from __future__ import annotations

import os
import shlex

names = [
    "PKCS11_CHECK_MODULE",
    "PKCS11_CHECK_PIN",
    "PKCS11_CHECK_SO_PIN",
    "PKCS11_CHECK_SLOT",
    "PKCS11_CHECK_INTERFACE",
    "PKCS11_CHECK_ISOLATION",
    "PKCS11_CHECK_TIMEOUT",
    "PKCS11_CHECK_CATEGORY",
    "PKCS11_CHECK_MATCH",
    "PKCS11_CHECK_MARKER",
    "PKCS11_CHECK_MAX_CRASHES_PER_FILE",
    "PKCS11_CHECK_DESTRUCTIVE",
    "PKCS11_CHECK_EXTRA_ARGS",
    "PKCS11_CHECK_TARGETS",
]
print("export PKCS11_CHECK_ARTIFACT_DIR=/mnt/pkcs11-check/artifacts")
for name in names:
    if name in os.environ:
        print(f"export {name}={shlex.quote(os.environ[name])}")
PY

export PKCS11_CHECK_OPTEE_SHARE_DIR="$share_dir"
export PKCS11_CHECK_OPTEE_SECURE_DIR="$secure_dir"

qemu_extra_args=(
    -fsdev "local,id=fsdev0,path=$share_dir,security_model=none"
    -device "virtio-9p-device,fsdev=fsdev0,mount_tag=host"
    -fsdev "local,id=fsdev1,path=$secure_dir,security_model=mapped-xattr"
    -device "virtio-9p-device,fsdev=fsdev1,mount_tag=secure"
)
printf -v qemu_extra '%q ' "${qemu_extra_args[@]}"
qemu_extra="${qemu_extra% }"

optee_make_args=(
    CFG_PKCS11_TA=y
    CFG_PKCS11_TA_ALLOW_DIGEST_KEY=y
    CFG_PKCS11_TA_AUTH_TEE_IDENTITY=y
    CFG_PKCS11_TA_CHECK_VALUE_ATTRIBUTE=y
    CFG_PKCS11_TA_RSA_X_509=y
    "CFG_PKCS11_TA_HEAP_SIZE=(128 * 1024)"
    QEMU_VIRTFS_ENABLE=y
    QEMU_PSS_ENABLE=y
    RUST_ENABLE=n
    BR2_PACKAGE_PYTHON3=y
    BR2_PACKAGE_PYTHON3_PYEXPAT=y
    BR2_PACKAGE_PYTHON3_ZLIB=y
    BR2_PACKAGE_OPENSC=y
)

cp /app/docker/optee-pkcs11/optee-pkcs11.exp /optee/build/qemu-check.exp
chmod +x /optee/build/qemu-check.exp

make -C /optee/build \
    "${optee_make_args[@]}" \
    QEMU_EXTRA_ARGS="$qemu_extra" \
    DUMP_LOGS_ON_ERROR=y \
    check

cp -a "$share_dir/artifacts/." "$artifact_dir/"
cp /optee/out/bin/serial0.log "$artifact_dir/serial0.log"
cp /optee/out/bin/serial1.log "$artifact_dir/serial1.log"

for required in results.json state.json quality.json report.jsonl serial0.log serial1.log; do
    if [[ ! -s "$artifact_dir/$required" ]]; then
        echo "missing OP-TEE artifact: $artifact_dir/$required" >&2
        exit 1
    fi
done
