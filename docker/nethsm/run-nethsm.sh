#!/usr/bin/env bash
# Start the co-located NetHSM (keyfender + etcd) via the image's own /start.sh, wait until
# Operational, create the operator user the PKCS#11 module logs in as, then run the suite.
# All over loopback — works under `network_mode: none`.
set -uo pipefail

# Credentials must match docker/nethsm/p11nethsm.conf.
ADMIN_PASS="Administrator1"
UNLOCK_PASS="UnlockPassphrase1"
OP_USER="operator"
OP_PASS="opPassphrase1"
BASE="https://127.0.0.1:8443/api/v1"

cleanup() { kill "${START_PID:-}" 2>/dev/null || true; }
trap cleanup EXIT

echo "NetHSM: starting keyfender+etcd via /start.sh (auto-provision)..."
# /start.sh auto-provisions (admin + unlock + systemTime) when ADMINPW is set, starts etcd
# and /keyfender.unix on 127.0.0.1:8443, then waits. Run it in the background.
ADMINPW="$ADMIN_PASS" UNLOCKPW="$UNLOCK_PASS" /start.sh >/tmp/nethsm-server.log 2>&1 &
START_PID=$!

# Poll until Operational (bounded ~60s: server boot + the provision the script fires).
state=""
for _ in $(seq 1 600); do
    state=$(curl -sk "$BASE/health/state" 2>/dev/null | grep -o '"state":"[A-Za-z]*"' | cut -d'"' -f4 || true)
    [ "$state" = "Operational" ] && break
    sleep 0.1
done
echo "NetHSM: state=$state"
if [ "$state" != "Operational" ]; then
    echo "NetHSM: server did not reach Operational; last log lines:" >&2
    tail -n 20 /tmp/nethsm-server.log >&2 || true
    exit 1
fi

# Create the operator user the .so uses (idempotent: a 2nd PUT on an existing id is fine).
# /start.sh provisions only the administrator + unlock passphrase, not an operator.
curl -sk -u "admin:$ADMIN_PASS" -X PUT "$BASE/users/$OP_USER" \
    -H "content-type: application/json" \
    -d "{\"realName\":\"pkcs11-check operator\",\"role\":\"Operator\",\"passphrase\":\"$OP_PASS\"}" \
    >/tmp/nethsm-operator.log 2>&1 || true
echo "NetHSM: operator user ensured"

export P11NETHSM_CONFIG_FILE=/etc/nitrokey/p11nethsm.conf
export PKCS11_CHECK_MODULE=/usr/lib/libnethsm_pkcs11.so
exec bash /app/docker/run-pkcs11-check.sh
