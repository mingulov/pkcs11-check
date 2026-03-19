#!/usr/bin/env bash
# NSS softokn — uses system-installed libnss3/libsoftokn3
# No build required — system package provides the module.
#
# Two modes:
#   Slot 0 (crypto services): no PIN, no configDir, limited operations
#   Slot 1 (cert DB): needs configDir + PIN, full PKCS#11 operations
#
# This provider sets up slot 1 with a writable NSS cert DB.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${SCRIPT_DIR}/../data/nss-softokn"

MODULE="/usr/lib/x86_64-linux-gnu/libsoftokn3.so"
# Slot 0 = NSS Internal Cryptographic Services (no PIN, no configDir needed)
# Slot 1 = NSS User Private Key and Certificate Services (needs configDir + PIN)
SLOT=0
TOKEN_LABEL="NSS Internal Cryptographic Services"
PIN=""

build() {
    # No build needed — system package
    if [[ ! -f "$MODULE" ]]; then
        echo "ERROR: NSS softokn not installed. Install: sudo apt install libnss3 libnss3-tools"
        return 1
    fi
    echo "NSS softokn: using system $(dpkg-query -W -f='${Version}' libnss3 2>/dev/null || echo 'unknown')"
}

setup() {
    export PROVIDER_NAME="nss-softokn"
    export MODULE
    # Slot 0 doesn't need PIN or configDir
    unset PIN
    echo "NSS softokn ready: module=$MODULE slot=$SLOT (crypto services, no PIN)"
}

get_module() { echo "$MODULE"; }
get_slot()   { echo "$SLOT"; }
get_pin()    { echo "$PIN"; }
get_label()  { echo "$TOKEN_LABEL"; }
get_default_isolation() { echo "file"; }

get_env() {
    echo "NSS_LIB_PARAMS=configDir=sql:$DATA_DIR"
}
