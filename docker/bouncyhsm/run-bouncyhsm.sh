#!/usr/bin/env bash
set -euo pipefail

cleanup() {
    pkill -f "dotnet BouncyHsm.dll" 2>/dev/null || true
}

trap cleanup EXIT

echo "BouncyHSM starting..."
cd /opt/bouncyhsm
ASPNETCORE_ENVIRONMENT=Production ASPNETCORE_URLS=http://localhost:5000 \
    dotnet BouncyHsm.dll >/tmp/bouncyhsm-server.log 2>&1 &
sleep 4

cd /app
if [[ ! -f /usr/lib/libbouncyhsm_pkcs11.so ]]; then
    echo "BouncyHSM: native PKCS#11 lib not available"
    exit 0
fi

curl -sf -X POST http://localhost:5000/Slot \
    -H "Content-Type: application/json" \
    -d '{"IsHwDevice":false,"Description":"pkcs11-check","Token":{"Label":"pkcs11-check","SerialNumber":"0001","UserPin":"1234","SoPin":"12345678","SimulateHwRng":true,"SimulateHwMechanism":true,"SimulateProtectedAuthPath":false,"SimulateQualifiedArea":false,"SpeedMode":"WithoutRestriction"}}'
echo
echo "Slot created — 206 mechanisms"

export PKCS11_CHECK_MODULE=/usr/lib/libbouncyhsm_pkcs11.so
bash /app/docker/run-pkcs11-check.sh
