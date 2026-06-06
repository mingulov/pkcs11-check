#!/usr/bin/env bash
# Kryoptic — Rust PKCS#11 token (v3.2, PQC support)
# Latest release: v1.5.1
# Requires: rustc 1.70+, OpenSSL 3.2+ (auto-detected from local-builds/openssl)

PROVIDER_NAME="kryoptic"
DEFAULT_BRANCH="v1.5.1"
REPO="https://github.com/latchset/kryoptic.git"

build() {
    local branch="${1:-$DEFAULT_BRANCH}"
    local src="$BASE_DIR/kryoptic/src"
    local lib="$BASE_DIR/kryoptic/lib"
    mkdir -p "$lib"

    echo "=== Building Kryoptic ($branch) ==="

    # Auto-detect local OpenSSL build
    local local_ossl="$BASE_DIR/openssl/install"
    if [ -d "$local_ossl" ] && [ -z "${OPENSSL_DIR:-}" ]; then
        echo "Using local OpenSSL: $local_ossl"
        export OPENSSL_DIR="$local_ossl"
        export PKG_CONFIG_PATH="$local_ossl/lib64/pkgconfig:$local_ossl/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
        export LD_LIBRARY_PATH="$local_ossl/lib64:$local_ossl/lib:${LD_LIBRARY_PATH:-}"
    fi

    if [ ! -d "$src" ]; then
        git clone --depth 1 --branch "$branch" "$REPO" "$src"
    elif [ "$branch" = "main" ]; then
        cd "$src" && git fetch origin main && git checkout main && git pull
    fi

    cd "$src"
    local features="standard,pqc,profiles,aes,log"
    echo "Features: $features"
    cargo build --release --features "$features"
    cp target/release/libkryoptic_pkcs11.so "$lib/"

    echo "Built: $lib/libkryoptic_pkcs11.so"
    ls -lh "$lib/libkryoptic_pkcs11.so"
}

setup() {
    local so="$BASE_DIR/kryoptic/lib/libkryoptic_pkcs11.so"
    [ -f "$so" ] || { echo "ERROR: Build first: bash local-builds/build.sh kryoptic"; exit 1; }

    # Set LD_LIBRARY_PATH for custom OpenSSL if present
    local local_ossl="$BASE_DIR/openssl/install"
    if [ -d "$local_ossl" ]; then
        export LD_LIBRARY_PATH="$local_ossl/lib64:$local_ossl/lib:${LD_LIBRARY_PATH:-}"
    fi

    local token_dir="$TOKENS_DIR/kryoptic"
    mkdir -p "$token_dir"
    local conf="$token_dir/token.conf"
    cat > "$conf" <<TOML
[[slots]]
slot = 1
dbtype = "sqlite"
dbargs = "$token_dir/token.sql"
TOML

    if [ ! -f "$token_dir/token.sql" ]; then
        echo "Initializing Kryoptic token..."
        KRYOPTIC_CONF="$conf" pkcs11-tool --module "$so" \
            --init-token --label "pkcs11-check" --so-pin 12345678 2>/dev/null || true
        KRYOPTIC_CONF="$conf" pkcs11-tool --module "$so" \
            --init-pin --pin 1234 --so-pin 12345678 2>/dev/null || true
    fi

    export KRYOPTIC_CONF="$conf"
    MODULE="$so"
    PIN="1234"
}
