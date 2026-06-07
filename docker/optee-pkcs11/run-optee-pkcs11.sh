#!/usr/bin/env bash
set -euo pipefail

artifact_dir="${PKCS11_CHECK_ARTIFACT_DIR:-/artifacts/optee-pkcs11}"
share_dir="${PKCS11_CHECK_OPTEE_SHARE_DIR:-/tmp/optee-pkcs11-share}"
secure_dir="${PKCS11_CHECK_OPTEE_SECURE_DIR:-/tmp/optee-pkcs11-secure}"
site_dir="${PKCS11_CHECK_GUEST_SITE_DIR:-/opt/pkcs11-check-site}"
data_dir="${PKCS11_CHECK_DATA_DIR:-/app/data}"
disabled_tests_file="${P11TEST_DISABLED_TESTS_FILE:-/app/disabled-tests.txt}"
progress_interval="${PKCS11_CHECK_OPTEE_PROGRESS_INTERVAL:-30}"
progress_pid=""

rm -rf "$share_dir" "$secure_dir"
mkdir -p "$artifact_dir" "$share_dir/artifacts" "$secure_dir"

cp -a "$site_dir" "$share_dir/site"
cp /app/docker/optee-pkcs11/guest-runner.py "$share_dir/guest-runner.py"
if [[ -d "$data_dir" ]]; then
    cp -a "$data_dir" "$share_dir/data"
    export PKCS11_CHECK_DATA_DIR=/mnt/pkcs11-check/data
fi
if [[ -f "$disabled_tests_file" ]]; then
    cp "$disabled_tests_file" "$share_dir/disabled-tests.txt"
    export P11TEST_DISABLED_TESTS_FILE=/mnt/pkcs11-check/disabled-tests.txt
fi
export PKCS11_CHECK_ISOLATION="${PKCS11_CHECK_ISOLATION:-file}"
export PKCS11_CHECK_NO_COLLECTION_CACHE="${PKCS11_CHECK_NO_COLLECTION_CACHE:-1}"
export PKCS11_CHECK_OPTEE_EXPECT_TIMEOUT="${PKCS11_CHECK_OPTEE_EXPECT_TIMEOUT:-7200}"

copy_optee_artifacts() {
    mkdir -p "$artifact_dir" 2>/dev/null || true
    if [[ -d "$share_dir/artifacts" ]]; then
        cp -a "$share_dir/artifacts/." "$artifact_dir/" 2>/dev/null || true
    fi
    if [[ -f /optee/out/bin/serial0.log ]]; then
        cp /optee/out/bin/serial0.log "$artifact_dir/serial0.log" 2>/dev/null || true
    fi
    if [[ -f /optee/out/bin/serial1.log ]]; then
        cp /optee/out/bin/serial1.log "$artifact_dir/serial1.log" 2>/dev/null || true
    fi
}

print_optee_progress_summary() {
    python3 - "$share_dir/artifacts/state.json" <<'PY' || true
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

state_path = Path(sys.argv[1])
if not state_path.exists():
    print("OP-TEE progress: waiting for guest runner artifacts")
    raise SystemExit

try:
    state = json.loads(state_path.read_text())
except json.JSONDecodeError:
    print("OP-TEE progress: guest runner state is updating")
    raise SystemExit

results = state.get("results") or []
units = state.get("units") or []
total = len(units) if units else "?"
counts = Counter(str(result.get("status", "unknown")) for result in results)
count_text = ", ".join(f"{status}={counts[status]}" for status in sorted(counts))
if not count_text:
    count_text = "no completed files yet"

last_text = "last=none"
if results:
    last = results[-1]
    target = Path(str(last.get("target", "unknown"))).name
    status = str(last.get("status", "unknown"))
    last_text = f"last={status} {target}"

print(f"OP-TEE progress: {len(results)}/{total} files complete ({count_text}); {last_text}")
PY
}

start_optee_progress_sync() {
    if [[ ! "$progress_interval" =~ ^[0-9]+$ ]]; then
        echo "invalid PKCS11_CHECK_OPTEE_PROGRESS_INTERVAL: $progress_interval" >&2
        exit 1
    fi
    if ((progress_interval == 0)); then
        return
    fi

    echo "OP-TEE progress: syncing artifacts every ${progress_interval}s to $artifact_dir"
    (
        trap - EXIT
        while true; do
            sleep "$progress_interval"
            copy_optee_artifacts
            print_optee_progress_summary
        done
    ) &
    progress_pid=$!
}

stop_optee_progress_sync() {
    if [[ -n "$progress_pid" ]]; then
        kill "$progress_pid" 2>/dev/null || true
        wait "$progress_pid" 2>/dev/null || true
        progress_pid=""
    fi
}

copy_optee_artifacts_on_exit() {
    rc=$?
    stop_optee_progress_sync
    copy_optee_artifacts
    exit "$rc"
}

trap copy_optee_artifacts_on_exit EXIT

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
    "PKCS11_CHECK_DATA_DIR",
    "P11TEST_DISABLED_TESTS_FILE",
    "PKCS11_CHECK_RV_TRACE",
    "PKCS11_CHECK_RV_TRACE_COMPACT",
    "PKCS11_CHECK_RV_TRACE_JOURNAL",
    "PKCS11_CHECK_RV_TRACE_JOURNAL_DIR",
    "PKCS11_CHECK_NO_COLLECTION_CACHE",
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

dump_qemu_logs() {
    for log in /optee/out/bin/serial0.log /optee/out/bin/serial1.log; do
        if [[ -f "$log" ]]; then
            echo "== $log:"
            cat "$log"
            echo "== end of $log:"
        fi
    done
}

run_prebuilt_qemu() {
    qemu_check_args=(
        -nographic
        -smp "${PKCS11_CHECK_OPTEE_QEMU_SMP:-2}"
        -cpu "${PKCS11_CHECK_OPTEE_QEMU_CPU:-max,sme=on,pauth-impdef=on}"
        -d unimp
        -semihosting-config enable=on,target=native
        -m "${PKCS11_CHECK_OPTEE_QEMU_MEM:-1057}"
        -bios bl1.bin
        -initrd rootfs.cpio.gz
        -kernel Image
        -append "console=ttyAMA0,38400 keep_bootcon root=/dev/vda2 ${PKCS11_CHECK_OPTEE_KERNEL_BOOTARGS:-}"
        -machine "${PKCS11_CHECK_OPTEE_QEMU_MACHINE:-virt,acpi=off,secure=on,mte=off,gic-version=3,virtualization=false}"
        "${qemu_extra_args[@]}"
        -serial mon:stdio
        -serial file:serial1.log
    )
    printf -v qemu_check '%q ' "${qemu_check_args[@]}"
    qemu_check="${qemu_check% }"

    ln -sf /optee/out-br/images/rootfs.cpio.gz /optee/out/bin/
    rm -f /optee/out/bin/serial0.log /optee/out/bin/serial1.log
    (
        cd /optee/out/bin
        export QEMU="${PKCS11_CHECK_OPTEE_QEMU:-/optee/qemu/build/qemu-system-aarch64}"
        export QEMU_CHECK_ARGS="$qemu_check"
        export XEN_BOOT=n
        export XEN_FFA=
        export RUST_ENABLE=n
        expect /app/docker/optee-pkcs11/optee-pkcs11.exp --
    ) || {
        dump_qemu_logs
        return 1
    }
}

run_make_check() {
    cp /app/docker/optee-pkcs11/optee-pkcs11.exp /optee/build/qemu-check.exp
    chmod +x /optee/build/qemu-check.exp
    make -C /optee/build \
        "${optee_make_args[@]}" \
        QEMU_EXTRA_ARGS="$qemu_extra" \
        DUMP_LOGS_ON_ERROR=y \
        check
}

start_optee_progress_sync
if [[ "${PKCS11_CHECK_OPTEE_USE_MAKE_CHECK:-0}" == "1" ]]; then
    run_make_check
else
    run_prebuilt_qemu
fi

stop_optee_progress_sync
copy_optee_artifacts

for required in results.json state.json quality.json report.jsonl serial0.log serial1.log; do
    if [[ ! -s "$artifact_dir/$required" ]]; then
        echo "missing OP-TEE artifact: $artifact_dir/$required" >&2
        exit 1
    fi
done
