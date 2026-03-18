#!/usr/bin/env bash
# Build BouncyHSM (.NET) locally.
# Usage: bash local-builds/build-bouncyhsm.sh
#
# Requires: dotnet SDK 8.0+ (https://dotnet.microsoft.com/download)
# Check: dotnet --version
#
# BouncyHSM is a .NET PKCS#11 token that communicates via TCP.
# The PKCS#11 .so is a native shim that proxies to the .NET server.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/bouncyhsm/src"
LIB="$SCRIPT_DIR/bouncyhsm/lib"
SERVER="$SCRIPT_DIR/bouncyhsm/server"
mkdir -p "$LIB" "$SERVER"

echo "=== Building BouncyHSM ==="

if ! command -v dotnet &>/dev/null; then
    echo "ERROR: dotnet SDK not found. Install from https://dotnet.microsoft.com/download"
    echo "Or skip BouncyHSM — it requires .NET runtime."
    exit 1
fi

if [ ! -d "$SRC" ]; then
    git clone --depth 1 https://github.com/harrison314/BouncyHsm.git "$SRC"
fi

cd "$SRC"

echo "Building server..."
dotnet publish src/Src/BouncyHsm/BouncyHsm.csproj -c Release -o "$SERVER" 2>&1 | tail -3

echo "Building native PKCS#11 shim..."
# The native lib needs to be extracted from NuGet
dotnet new console -o /tmp/bouncyhsm-extract --force 2>/dev/null
cd /tmp/bouncyhsm-extract
dotnet add package BouncyHsm.Pkcs11Lib 2>/dev/null
SO=$(find ~/.nuget/packages/bouncyhsm.pkcs11lib -name "libBouncyHsm.Pkcs11Lib.so" 2>/dev/null | head -1)

if [ -n "$SO" ]; then
    cp "$SO" "$LIB/libbouncyhsm_pkcs11.so"
    echo "Built: $LIB/libbouncyhsm_pkcs11.so"
    ls -lh "$LIB/libbouncyhsm_pkcs11.so"
else
    echo "WARNING: native .so not found in NuGet package"
    echo "BouncyHSM may need Docker for the native PKCS#11 library."
fi

echo ""
echo "Server: $SERVER/BouncyHsm.dll"
echo "To start: dotnet $SERVER/BouncyHsm.dll"
rm -rf /tmp/bouncyhsm-extract
