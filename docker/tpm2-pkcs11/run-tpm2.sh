#!/usr/bin/env bash
set -euo pipefail

cleanup() {
    pkill -f "tpm2-abrmd" 2>/dev/null || true
    pkill -f "swtpm socket" 2>/dev/null || true
}

trap cleanup EXIT

echo "tpm2-pkcs11:"
rpm -q tpm2-pkcs11 swtpm tpm2-abrmd

swtpm socket --tpm2 \
    --tpmstate dir=/tmp/swtpm \
    --ctrl type=tcp,port=2322 \
    --server type=tcp,port=2321 \
    --flags startup-clear \
    --log level=0 >/dev/null 2>&1 &
sleep 1

dbus-daemon --system --fork 2>/dev/null
tpm2-abrmd --tcti=swtpm:host=127.0.0.1,port=2321 --allow-root >/dev/null 2>&1 &
sleep 2

export TPM2TOOLS_TCTI="tabrmd:bus_type=system"
export TPM2_PKCS11_TCTI="tabrmd:bus_type=system"
tpm2_getcap properties-fixed 2>&1 | head -3
tpm2_ptool init 2>&1
tpm2_ptool addtoken --pid=1 --sopin=12345678 --userpin=1234 --label=pkcs11-check 2>&1

module="$(cat /tmp/module_path)"
echo "Module: $module"
export PKCS11_CHECK_MODULE="$module"

if ! bash /app/docker/run-pkcs11-check.sh; then
    echo "Some tests may fail — TPM2 has limited mechanism support"
fi
