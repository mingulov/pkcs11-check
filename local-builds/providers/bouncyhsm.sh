#!/usr/bin/env bash
# BouncyHSM — .NET/BouncyCastle PKCS#11 token (v3.2, 206 mechanisms)
# Requires: dotnet SDK 10.0+
# Architecture: .NET server + native PKCS#11 shim (TCP proxy)

PROVIDER_NAME="bouncyhsm"
DEFAULT_BRANCH="v2.0.1"
REPO="https://github.com/harrison314/BouncyHsm.git"
PATCH_FILE="$PROJECT_DIR/patches/bouncyhsm/0001-fix-getattributevalue-rvmethod.patch"

_apply_local_patch() {
    local src="$1"
    local apply_flags=(--ignore-space-change --ignore-whitespace)

    if [ ! -f "$PATCH_FILE" ]; then
        echo "ERROR: Missing patch file: $PATCH_FILE"
        exit 1
    fi

    if git -C "$src" apply "${apply_flags[@]}" --check "$PATCH_FILE" >/dev/null 2>&1; then
        echo "Applying local BouncyHSM patch..."
        git -C "$src" apply "${apply_flags[@]}" "$PATCH_FILE"
        return
    fi

    if git -C "$src" apply "${apply_flags[@]}" --reverse --check "$PATCH_FILE" >/dev/null 2>&1; then
        echo "Local BouncyHSM patch already applied."
        return
    fi

    echo "ERROR: Could not apply local patch: $PATCH_FILE"
    exit 1
}

build() {
    local branch="${1:-$DEFAULT_BRANCH}"
    local src="$BASE_DIR/bouncyhsm/src"
    local server="$BASE_DIR/bouncyhsm/server"
    local lib="$BASE_DIR/bouncyhsm/lib"
    local cc_bin=""
    mkdir -p "$lib" "$server"

    echo "=== Building BouncyHSM ($branch) ==="

    if ! command -v dotnet &>/dev/null; then
        echo "ERROR: dotnet SDK not found."
        echo "Install: curl -sSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 10.0 --install-dir ~/.dotnet"
        exit 1
    fi

    if ! command -v make &>/dev/null; then
        echo "ERROR: make not found."
        exit 1
    fi

    if command -v gcc &>/dev/null; then
        cc_bin="gcc"
    elif command -v clang &>/dev/null; then
        cc_bin="clang"
    else
        echo "ERROR: gcc or clang is required to build the native PKCS#11 shim."
        exit 1
    fi

    if [ ! -d "$src" ]; then
        git clone --depth 1 --branch "$branch" "$REPO" "$src"
    else
        git -C "$src" fetch --depth 1 origin "$branch" >/dev/null 2>&1 || git -C "$src" fetch --tags origin

        local current_commit=""
        local desired_commit=""
        current_commit="$(git -C "$src" rev-parse HEAD)"
        desired_commit="$(git -C "$src" rev-parse "$branch^{commit}")"

        if [ "$current_commit" != "$desired_commit" ]; then
            if [ -n "$(git -C "$src" status --porcelain)" ]; then
                echo "ERROR: local BouncyHSM source tree has local changes: $src"
                echo "Reset or remove it before switching to $branch."
                exit 1
            fi
            git -C "$src" checkout "$branch"
        fi
    fi

    _apply_local_patch "$src"

    cd "$src"
    echo "Building server..."
    dotnet publish src/Src/BouncyHsm/BouncyHsm.csproj -c Release -o "$server" \
        >"$BASE_DIR/bouncyhsm/dotnet-publish.log"
    tail -3 "$BASE_DIR/bouncyhsm/dotnet-publish.log"

    echo "Building native PKCS#11 shim from patched source..."
    make -C build_linux CC="$cc_bin"
    cp build_linux/BouncyHsm.Pkcs11Lib-x64.so "$lib/libbouncyhsm_pkcs11.so"
    echo "Built: $lib/libbouncyhsm_pkcs11.so"
    ls -lh "$lib/libbouncyhsm_pkcs11.so"

    echo ""
    echo "Server: dotnet $server/BouncyHsm.dll"
}

setup() {
    local so="$BASE_DIR/bouncyhsm/lib/libbouncyhsm_pkcs11.so"
    [ -f "$so" ] || { echo "ERROR: Build first: bash local-builds/build.sh bouncyhsm"; exit 1; }

    echo "NOTE: BouncyHSM server must be running."
    echo "  mkdir -p $BASE_DIR/bouncyhsm/data"
    echo "  cd $BASE_DIR/bouncyhsm/server"
    echo "  ASPNETCORE_ENVIRONMENT=Docker \\"
    echo "  ASPNETCORE_URLS=http://127.0.0.1:5011 \\"
    echo "  BouncyHsm_LiteDbPersistentRepositorySetup__DbFilePath=$BASE_DIR/bouncyhsm/data/BouncyHsm.db \\"
    echo "  BouncyHsm_BouncyHsmSetup__TcpEndpoint__Endpoint=127.0.0.1:8765 \\"
    echo "  dotnet BouncyHsm.dll"
    echo ""
    echo "Create a slot via API:"
    echo '  curl -X POST http://127.0.0.1:5011/Slot -H "Content-Type: application/json" \'
    echo '    -d '"'"'{"IsHwDevice":false,"Description":"pkcs11-check","Token":{"Label":"pkcs11-check","SerialNumber":"0001","UserPin":"1234","SoPin":"12345678"}}'"'"

    MODULE="$so"
    PIN="1234"
}

get_env() {
    echo "BOUNCY_HSM_CFG_STRING=Server=127.0.0.1;Port=8765;"
}
