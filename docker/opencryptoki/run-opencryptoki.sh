#!/usr/bin/env bash
set -euo pipefail

cleanup() {
    killall pkcsslotd 2>/dev/null || true
}

trap cleanup EXIT

echo "OpenCryptoki:"
rpm -q opencryptoki opencryptoki-swtok 2>/dev/null || echo "(built from source)"

pkcsslotd
sleep 2

echo "pkcs11-check" | pkcsconf -I -c 0 -S 87654321 2>&1 || true
printf "87654321\n1234\n1234\n" | pkcsconf -u -c 0 2>&1 || true
pkcsconf -t -c 0 2>&1

bash /app/docker/run-pkcs11-check.sh
