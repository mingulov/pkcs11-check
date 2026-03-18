#!/usr/bin/env bash
# BouncyHSM — .NET/BouncyCastle PKCS#11 token (v3.2, 206 mechanisms)
# Requires: dotnet SDK 10.0+
# Architecture: .NET server + native PKCS#11 shim (TCP proxy)

PROVIDER_NAME="bouncyhsm"
REPO="https://github.com/harrison314/BouncyHsm.git"

build() {
    local src="$BASE_DIR/bouncyhsm/src"
    local server="$BASE_DIR/bouncyhsm/server"
    local lib="$BASE_DIR/bouncyhsm/lib"
    mkdir -p "$lib" "$server"

    echo "=== Building BouncyHSM ==="

    if ! command -v dotnet &>/dev/null; then
        echo "ERROR: dotnet SDK not found."
        echo "Install: curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 10.0 --install-dir ~/.dotnet"
        exit 1
    fi

    if [ ! -d "$src" ]; then
        git clone --depth 1 "$REPO" "$src"
    fi

    cd "$src"
    echo "Building server..."
    dotnet publish src/Src/BouncyHsm/BouncyHsm.csproj -c Release -o "$server" 2>&1 | tail -3

    # Get native PKCS#11 shim from NuGet (BouncyHsm.Client package)
    echo "Extracting native PKCS#11 lib from NuGet..."
    local tmpdir=$(mktemp -d)
    cd "$tmpdir"
    dotnet new console -o . --force 2>/dev/null
    dotnet add package BouncyHsm.Client 2>/dev/null
    local so=$(find ~/.nuget -name "*.so" -path "*/linux-x64/*" 2>/dev/null | head -1)
    if [ -n "$so" ]; then
        cp "$so" "$lib/libbouncyhsm_pkcs11.so"
        echo "Built: $lib/libbouncyhsm_pkcs11.so"
        ls -lh "$lib/libbouncyhsm_pkcs11.so"
    else
        echo "WARNING: native .so not found in NuGet"
    fi
    rm -rf "$tmpdir"

    echo ""
    echo "Server: dotnet $server/BouncyHsm.dll"
}

setup() {
    local so="$BASE_DIR/bouncyhsm/lib/libbouncyhsm_pkcs11.so"
    [ -f "$so" ] || { echo "ERROR: Build first: bash local-builds/build.sh bouncyhsm"; exit 1; }

    echo "NOTE: BouncyHSM server must be running."
    echo "  dotnet $BASE_DIR/bouncyhsm/server/BouncyHsm.dll"
    echo ""
    echo "Create a slot via API:"
    echo '  curl -X POST http://localhost:5000/Slot -H "Content-Type: application/json" \'
    echo '    -d '"'"'{"IsHwDevice":false,"Description":"p11test","Token":{"Label":"p11test","SerialNumber":"0001","UserPin":"1234","SoPin":"12345678"}}'"'"

    MODULE="$so"
    PIN="1234"
}
