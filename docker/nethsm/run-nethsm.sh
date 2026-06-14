#!/usr/bin/env bash
# Start the co-located NetHSM (keyfender + etcd), provision it, create the operator user the
# PKCS#11 module logs in as, then run the suite. All over loopback — works under
# `network_mode: none`.
set -uo pipefail

# Credentials must match docker/nethsm/p11nethsm.conf.
ADMIN_PASS="Administrator1"
UNLOCK_PASS="UnlockPassphrase1"
OP_USER="operator"
OP_PASS="opPassphrase1"
BASE="https://127.0.0.1:8443/api/v1"

cleanup() { kill "${START_PID:-}" 2>/dev/null || true; }
trap cleanup EXIT

get_state() {
    curl -sk "$BASE/health/state" 2>/dev/null | grep -o '"state":"[A-Za-z]*"' | cut -d'"' -f4
}

echo "NetHSM: starting keyfender+etcd via /start.sh ..."
# Start the server only. We deliberately do NOT set ADMINPW (which would trigger /start.sh's
# built-in auto-provision) because that path uses `date --utc`, a GNU long option Alpine's
# busybox does not support, yielding a bad systemTime. We provision explicitly below instead.
/start.sh >/tmp/nethsm-server.log 2>&1 &
START_PID=$!

# Wait for the server to SETTLE into a real state, bounded ~60s. etcd takes a few seconds to
# boot; until it is healthy keyfender reports a transient "Failed" state, so we must wait for
# "Unprovisioned"/"Operational" rather than the first non-empty response.
state=""
for _ in $(seq 1 600); do
    state=$(get_state)
    case "$state" in
        Unprovisioned | Operational) break ;;
    esac
    sleep 0.1
done
echo "NetHSM: settled state=$state"

if [ "$state" = "Unprovisioned" ]; then
    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "NetHSM: provisioning (systemTime=$now)..."
    code=$(curl -sk -o /tmp/nethsm-provision.log -w '%{http_code}' -X POST "$BASE/provision" \
        -H "content-type: application/json" \
        -d "{\"unlockPassphrase\":\"$UNLOCK_PASS\",\"adminPassphrase\":\"$ADMIN_PASS\",\"systemTime\":\"$now\"}")
    echo "NetHSM: provision HTTP $code"
    [ "$code" = "200" ] || [ "$code" = "204" ] || { echo "NetHSM: provision response:"; cat /tmp/nethsm-provision.log; }
fi

# Wait for Operational, bounded ~60s.
for _ in $(seq 1 600); do
    state=$(get_state)
    [ "$state" = "Operational" ] && break
    sleep 0.1
done
echo "NetHSM: state=$state"
if [ "$state" != "Operational" ]; then
    echo "NetHSM: did not reach Operational; server log:" >&2
    cat /tmp/nethsm-server.log >&2 || true
    exit 1
fi

# Create the operator user the .so logs in as (admin-authenticated; /provision creates only the
# administrator). Idempotent: a repeat PUT on an existing id is harmless.
ocode=$(curl -sk -o /tmp/nethsm-operator.log -w '%{http_code}' -u "admin:$ADMIN_PASS" \
    -X PUT "$BASE/users/$OP_USER" -H "content-type: application/json" \
    -d "{\"realName\":\"pkcs11-check operator\",\"role\":\"Operator\",\"passphrase\":\"$OP_PASS\"}")
echo "NetHSM: create operator HTTP $ocode"

export P11NETHSM_CONFIG_FILE=/etc/nitrokey/p11nethsm.conf
export PKCS11_CHECK_MODULE=/usr/lib/libnethsm_pkcs11.so
exec bash /app/docker/run-pkcs11-check.sh
