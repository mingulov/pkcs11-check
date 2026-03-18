#!/usr/bin/env bash
# Build soft tokens locally for fast testing.
# Usage: bash local-builds/build.sh [kryoptic|softhsm2|pkcs11-mock|all]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

build_kryoptic() {
    echo "=== Building Kryoptic ==="
    local src="$SCRIPT_DIR/kryoptic/src"
    local lib="$SCRIPT_DIR/kryoptic/lib"
    mkdir -p "$lib"

    if [ ! -d "$src" ]; then
        git clone --depth 1 --branch v1.5.0 https://github.com/latchset/kryoptic.git "$src"
    else
        echo "Source exists at $src (use 'rm -rf $src' to re-clone)"
    fi

    cd "$src"
    cargo build --release
    cp target/release/libkryoptic_pkcs11.so "$lib/"
    echo "Built: $lib/libkryoptic_pkcs11.so"
    ls -lh "$lib/libkryoptic_pkcs11.so"
}

build_softhsm2() {
    echo "=== Building SoftHSM2 ==="
    local src="$SCRIPT_DIR/softhsm2/src"
    local prefix="$SCRIPT_DIR/softhsm2/install"
    local lib="$SCRIPT_DIR/softhsm2/lib"
    mkdir -p "$lib"

    if [ ! -d "$src" ]; then
        git clone --depth 1 --branch 2.7.0 https://github.com/softhsm/SoftHSMv2.git "$src"
    else
        echo "Source exists at $src"
    fi

    cd "$src"
    if [ ! -f configure ]; then
        sh autogen.sh
    fi
    if [ ! -f Makefile ]; then
        ./configure --prefix="$prefix" --disable-gost
    fi
    make -j"$(nproc)"
    make install

    # Find the built .so
    local so=$(find "$prefix" -name "libsofthsm2.so" | head -1)
    if [ -n "$so" ]; then
        cp "$so" "$lib/"
        echo "Built: $lib/libsofthsm2.so"
        ls -lh "$lib/libsofthsm2.so"
    else
        echo "ERROR: libsofthsm2.so not found after build"
        exit 1
    fi
}

build_pkcs11_mock() {
    echo "=== Building pkcs11-mock ==="
    local src="$SCRIPT_DIR/pkcs11-mock/src"
    local lib="$SCRIPT_DIR/pkcs11-mock/lib"
    mkdir -p "$lib"

    if [ ! -d "$src" ]; then
        git clone --depth 1 https://github.com/pspacek/pkcs11-mock.git "$src"
    else
        echo "Source exists at $src"
    fi

    cd "$src"
    mkdir -p build && cd build
    cmake ..
    make -j"$(nproc)"

    local so=$(find . -name "*.so" | head -1)
    if [ -n "$so" ]; then
        cp "$so" "$lib/pkcs11-mock.so"
        echo "Built: $lib/pkcs11-mock.so"
        ls -lh "$lib/pkcs11-mock.so"
    else
        echo "ERROR: .so not found after build"
        exit 1
    fi
}

case "${1:-all}" in
    kryoptic)   build_kryoptic ;;
    softhsm2)   build_softhsm2 ;;
    pkcs11-mock) build_pkcs11_mock ;;
    all)
        build_kryoptic
        build_softhsm2
        build_pkcs11_mock
        ;;
    *)
        echo "Usage: $0 [kryoptic|softhsm2|pkcs11-mock|all]"
        exit 1
        ;;
esac

echo ""
echo "=== Done ==="
