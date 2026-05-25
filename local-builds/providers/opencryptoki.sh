#!/usr/bin/env bash
# OpenCryptoki — C PKCS#11 token (v3.0, IBM)
# Latest release: v3.27.0
# Requires: gcc, automake, autoconf, libtool, libssl-dev, libcap-dev, libldap2-dev
# NOTE: Needs pkcsslotd daemon running for operation.

PROVIDER_NAME="opencryptoki"
DEFAULT_BRANCH="v3.27.0"
REPO="https://github.com/opencryptoki/opencryptoki.git"

build() {
    local branch="${1:-$DEFAULT_BRANCH}"
    local src="$BASE_DIR/opencryptoki/src"
    local prefix="$BASE_DIR/opencryptoki/install"
    local lib="$BASE_DIR/opencryptoki/lib"
    mkdir -p "$lib"

    echo "=== Building OpenCryptoki ($branch) ==="

    if [ ! -d "$src" ]; then
        git clone --depth 1 --branch "$branch" "$REPO" "$src"
    elif [ "$branch" = "master" ]; then
        cd "$src" && git fetch origin master && git checkout master && git pull
    fi

    cd "$src"
    [ -f configure ] || ./bootstrap.sh

    local configure_args=(
        --prefix="$prefix"
        --enable-swtok --disable-tpmtok --disable-ccatok
        --disable-ep11tok --disable-icatok
    )

    if [ -n "${OPENSSL_DIR:-}" ]; then
        configure_args+=(
            "LDFLAGS=-L$OPENSSL_DIR/lib -Wl,-rpath,$OPENSSL_DIR/lib"
            "CPPFLAGS=-I$OPENSSL_DIR/include"
            "PKG_CONFIG_PATH=$OPENSSL_DIR/lib/pkgconfig"
        )
    fi

    [ -f Makefile ] || ./configure "${configure_args[@]}"
    make -j"$(nproc)"
    make install 2>/dev/null || true

    local so=$(find "$prefix" "$src" -name "libopencryptoki.so" -path "*/.libs/*" -o -name "libopencryptoki.so" -path "*/lib/*" 2>/dev/null | head -1)
    [ -n "$so" ] && cp "$so" "$lib/"

    echo "Built: $lib/libopencryptoki.so"
    ls -lh "$lib/libopencryptoki.so"
    echo ""
    echo "To run: sudo $prefix/sbin/pkcsslotd"
}

setup() {
    local so="$BASE_DIR/opencryptoki/lib/libopencryptoki.so"
    [ -f "$so" ] || { echo "ERROR: Build first: bash local-builds/build.sh opencryptoki"; exit 1; }
    echo "NOTE: OpenCryptoki needs pkcsslotd running."
    echo "  sudo $BASE_DIR/opencryptoki/install/sbin/pkcsslotd"
    MODULE="$so"
    PIN="1234"
}
