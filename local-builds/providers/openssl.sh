#!/usr/bin/env bash
# OpenSSL — dependency for Kryoptic, SoftHSM2, OpenCryptoki
# Latest release: openssl-3.6.1
# Not a PKCS#11 provider itself — just a build dependency.

PROVIDER_NAME="openssl"
DEFAULT_BRANCH="openssl-3.6.1"
REPO="https://github.com/openssl/openssl.git"

build() {
    local branch="${1:-$DEFAULT_BRANCH}"
    local src="$BASE_DIR/openssl/src"
    local prefix="$BASE_DIR/openssl/install"
    mkdir -p "$prefix"

    echo "=== Building OpenSSL ($branch) ==="

    if [ ! -d "$src" ]; then
        git clone --depth 1 --branch "$branch" "$REPO" "$src"
    elif [ "$branch" = "master" ]; then
        cd "$src" && git fetch origin master && git checkout master && git pull
    fi

    cd "$src"
    [ -f Makefile ] || ./Configure --prefix="$prefix" --openssldir="$prefix/ssl" shared no-tests
    make -j"$(nproc)"
    make install_sw

    echo "Built: $prefix"
    "$prefix/bin/openssl" version
    echo ""
    echo "To use: export OPENSSL_DIR=$prefix"
}

setup() {
    echo "OpenSSL is a build dependency, not a PKCS#11 provider."
    echo "Use: export OPENSSL_DIR=$BASE_DIR/openssl/install"
    exit 1
}
