#!/usr/bin/env bash
# tpm2-pkcs11 with swtpm (software TPM emulator)
# No hardware TPM or tss group needed — runs entirely in userspace.
#
# Requires: swtpm, tpm2-tools, tpm2-abrmd, dbus-daemon, libtpm2-pkcs11-1
#   apt install swtpm swtpm-tools tpm2-tools tpm2-abrmd dbus libtpm2-pkcs11-1 python3-tpm2-pkcs11-tools
#
# Architecture: swtpm (TCP) → tpm2-abrmd (D-Bus) → libtpm2_pkcs11.so

PROVIDER_NAME="tpm2-swtpm"
# NOTE: swtpm requires background daemons. Run setup manually first:
#
#   # 1. Start swtpm
#   mkdir -p local-builds/tokens/tpm2-swtpm/swtpm-state
#   swtpm socket --tpm2 --tpmstate dir=local-builds/tokens/tpm2-swtpm/swtpm-state \
#     --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags startup-clear &
#
#   # 2. Start abrmd (needs sudo for dbus)
#   sudo tpm2-abrmd --tcti=swtpm:host=127.0.0.1,port=2321 --allow-root &
#
#   # 3. Init token
#   export TPM2TOOLS_TCTI='swtpm:host=127.0.0.1,port=2321'
#   export TPM2_PKCS11_TCTI='swtpm:host=127.0.0.1,port=2321'
#   export TPM2_PKCS11_STORE=local-builds/tokens/tpm2-swtpm
#   python3 -m tpm2_pkcs11.tpm2_ptool init
#   python3 -m tpm2_pkcs11.tpm2_ptool addtoken --pid=1 --sopin=12345678 --userpin=1234 --label=p11test
#
#   # 4. Test
#   bash local-builds/test.sh tpm2-swtpm -k test_slot -v

build() {
    echo "=== tpm2-swtpm (software TPM) ==="
    echo "No build needed — uses system packages."
    echo ""

    local missing=""
    command -v swtpm &>/dev/null || missing="$missing swtpm"
    command -v tpm2-abrmd &>/dev/null || missing="$missing tpm2-abrmd"
    command -v dbus-daemon &>/dev/null || missing="$missing dbus"
    [ -f /usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so ] || missing="$missing libtpm2-pkcs11-1"

    if [ -n "$missing" ]; then
        echo "Missing packages:$missing"
        echo "Install: sudo apt install swtpm swtpm-tools tpm2-tools tpm2-abrmd dbus libtpm2-pkcs11-1 python3-tpm2-pkcs11-tools"
        exit 1
    fi

    echo "All dependencies present."
}

_start_swtpm() {
    local token_dir="$1"
    local swtpm_dir="$token_dir/swtpm-state"
    mkdir -p "$swtpm_dir"

    # Check if already running
    if pgrep -f "swtpm.*$swtpm_dir" &>/dev/null; then
        echo "swtpm already running for $swtpm_dir"
        return 0
    fi

    echo "Starting swtpm..."
    swtpm socket --tpm2 \
        --tpmstate dir="$swtpm_dir" \
        --ctrl type=tcp,port=2322 \
        --server type=tcp,port=2321 \
        --flags startup-clear \
        --log level=0 &>/dev/null &
    sleep 1

    if ! pgrep -f "swtpm.*socket" &>/dev/null; then
        echo "ERROR: swtpm failed to start"
        return 1
    fi
    echo "swtpm running (TCP port 2321)"
}

_start_abrmd() {
    # Check if already running
    if pgrep -f tpm2-abrmd &>/dev/null; then
        echo "tpm2-abrmd already running"
        return 0
    fi

    # Start dbus if needed
    if [ ! -S /run/dbus/system_bus_socket ] && [ ! -S /var/run/dbus/system_bus_socket ]; then
        echo "Starting dbus..."
        sudo dbus-daemon --system --fork 2>/dev/null || true
        sleep 1
    fi

    echo "Starting tpm2-abrmd..."
    sudo tpm2-abrmd --tcti=swtpm:host=127.0.0.1,port=2321 --allow-root &>/dev/null &
    sleep 2

    if ! pgrep -f tpm2-abrmd &>/dev/null; then
        echo "ERROR: tpm2-abrmd failed to start"
        return 1
    fi
    echo "tpm2-abrmd running"
}

_init_token() {
    local token_dir="$1"

    export TPM2TOOLS_TCTI='tabrmd:bus_type=system'
    export TPM2_PKCS11_TCTI='tabrmd:bus_type=system'
    export TPM2_PKCS11_STORE="$token_dir"

    if [ -f "$token_dir/tpm2_pkcs11.sqlite3" ]; then
        echo "Token already initialized at $token_dir"
        return 0
    fi

    echo "Initializing tpm2-pkcs11 token..."
    python3 -m tpm2_pkcs11.tpm2_ptool init 2>&1
    python3 -m tpm2_pkcs11.tpm2_ptool addtoken --pid=1 --sopin=12345678 --userpin=1234 --label=p11test 2>&1
}

setup() {
    local so="/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so"
    [ -f "$so" ] || { echo "ERROR: libtpm2-pkcs11-1 not installed"; exit 1; }

    local token_dir="$TOKENS_DIR/tpm2-swtpm"
    mkdir -p "$token_dir"

    _start_swtpm "$token_dir" || exit 1
    _start_abrmd || exit 1
    _init_token "$token_dir" || exit 1

    export TPM2TOOLS_TCTI='tabrmd:bus_type=system'
    export TPM2_PKCS11_TCTI='tabrmd:bus_type=system'
    export TPM2_PKCS11_STORE="$token_dir"

    MODULE="$so"
    PIN="1234"
}

# Cleanup function — call after testing
cleanup() {
    echo "Stopping tpm2-abrmd and swtpm..."
    sudo pkill tpm2-abrmd 2>/dev/null || true
    pkill -f "swtpm.*socket" 2>/dev/null || true
    echo "Stopped."
}
