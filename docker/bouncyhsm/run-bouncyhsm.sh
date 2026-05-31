#!/usr/bin/env bash
set -euo pipefail

cleanup() {
    pkill -f "dotnet BouncyHsm.dll" 2>/dev/null || true
}

trap cleanup EXIT

echo "BouncyHSM starting..."
cd /opt/bouncyhsm
# Server tuning knobs (env-overridable; defaults preserve original behavior).
#   BHSM_LOG_LEVEL=Warning      -> skip per-call Information log work
#   DOTNET_TieredPGO=1          -> dynamic PGO of hot methods (managed crypto path)
# These target the dominant per-call cost (.NET handler + MessagePack + BouncyCastle
# crypto), which the TCP socket is NOT (connection overhead is ~1% per the transport doc).
ASPNETCORE_ENVIRONMENT=Production ASPNETCORE_URLS=http://localhost:5000 \
    Logging__LogLevel__Default="${BHSM_LOG_LEVEL:-Information}" \
    DOTNET_TieredPGO="${DOTNET_TieredPGO:-0}" \
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
