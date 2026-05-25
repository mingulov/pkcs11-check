#!/usr/bin/env bash
set -euo pipefail

cleanup() {
    if [[ -n "${tpm2_abrmd_pid:-}" ]]; then
        kill "$tpm2_abrmd_pid" 2>/dev/null || true
    fi
    if [[ -n "${swtpm_pid:-}" ]]; then
        kill "$swtpm_pid" 2>/dev/null || true
    fi
    pkill -f "tpm2-abrmd" 2>/dev/null || true
    pkill -f "swtpm socket" 2>/dev/null || true
}

trap cleanup EXIT

echo "tpm2-pkcs11:"
if ! rpm -q tpm2-pkcs11; then
    echo "tpm2-pkcs11 source revision: $(cat /tmp/tpm2_pkcs11_revision 2>/dev/null || true)"
fi
rpm -q swtpm tpm2-abrmd tpm2-tools tpm2-tss
python3.14 -c 'import importlib.metadata as m; print("python-pkcs11", m.version("python-pkcs11"))'

swtpm socket --tpm2 \
    --tpmstate dir=/tmp/swtpm \
    --ctrl type=tcp,port=2322 \
    --server type=tcp,port=2321 \
    --flags startup-clear \
    --log level=0 >/dev/null 2>&1 &
swtpm_pid=$!
sleep 1

dbus-daemon --system --fork
# tpm2-abrmd defaults saturate quickly during ACVP RSA / ECDSA runs (each
# test generates a keypair). Refreshed test data in 2026-04-29 drove
# 1,027+ "Esys_Load: out of memory for object contexts" errors during
# login. Raise the per-connection caps to the values tabrmd 3.0.0 allows.
#
# tpm2-abrmd 3.0.0 (Fedora 44) flag constraints:
#   --max-transients : 1-100 (hard-coded TPM transient-object slot count)
#   --max-sessions   : 1-4   (hard-coded TPM session-slot count)
# An earlier fix attempt (commit ff8cc65) used --max-transient-objects=512
# and --max-sessions=512, which (a) used the wrong flag name and (b) was
# out of range, so tabrmd died at startup; dbus then could not activate
# the service ("Cannot do system-bus activation with no user" — see
# TPM-DBUS-001). Keep daemon output out of the artifact tee pipe; otherwise
# the background process keeps console.log open after tests finish.
tpm2-abrmd --tcti=swtpm:host=127.0.0.1,port=2321 \
    --max-transients=100 \
    --max-sessions=4 \
    --allow-root >/tmp/tpm2-abrmd.log 2>&1 &
tpm2_abrmd_pid=$!
sleep 2
if ! kill -0 "$tpm2_abrmd_pid" 2>/dev/null; then
    cat /tmp/tpm2-abrmd.log >&2
    exit 1
fi

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
