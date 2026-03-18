#!/usr/bin/env bash
# SoftHSM2 — C++ PKCS#11 token (v2.40)
# Latest release: 2.7.0
# Requires: gcc, g++, libssl-dev, libsqlite3-dev, automake, autoconf, libtool

PROVIDER_NAME="softhsm2"
DEFAULT_BRANCH="2.7.0"
REPO="https://github.com/softhsm/SoftHSMv2.git"

build() {
    local branch="${1:-$DEFAULT_BRANCH}"
    local src="$BASE_DIR/softhsm2/src"
    local prefix="$BASE_DIR/softhsm2/install"
    local lib="$BASE_DIR/softhsm2/lib"
    mkdir -p "$lib"

    echo "=== Building SoftHSM2 ($branch) ==="

    if [ ! -d "$src" ]; then
        git clone --depth 1 --branch "$branch" "$REPO" "$src"
    elif [ "$branch" = "master" ]; then
        cd "$src" && git fetch origin master && git checkout master && git pull
    fi

    cd "$src"
    [ -f configure ] || sh autogen.sh

    local configure_args=(--prefix="$prefix" --disable-gost)

    if [ -n "${OPENSSL_DIR:-}" ]; then
        echo "Using custom OpenSSL: $OPENSSL_DIR"
        configure_args+=(
            "--with-openssl=$OPENSSL_DIR"
            "LDFLAGS=-L$OPENSSL_DIR/lib -Wl,-rpath,$OPENSSL_DIR/lib"
            "CPPFLAGS=-I$OPENSSL_DIR/include"
        )
    fi

    [ -f Makefile ] || ./configure "${configure_args[@]}"
    make -j"$(nproc)"
    make install 2>/dev/null || true  # install may fail on system dirs, that's OK

    local so=$(find "$prefix" "$src" -name "libsofthsm2.so" -path "*/.libs/*" -o -name "libsofthsm2.so" -path "*/lib/*" 2>/dev/null | head -1)
    [ -n "$so" ] && cp "$so" "$lib/"

    echo "Built: $lib/libsofthsm2.so"
    ls -lh "$lib/libsofthsm2.so"
}

setup() {
    # Determine which .so to use
    local so="$BASE_DIR/softhsm2/lib/libsofthsm2.so"
    if [ ! -f "$so" ]; then
        # Fallback to system SoftHSM2
        so="/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
    fi
    [ -f "$so" ] || { echo "ERROR: SoftHSM2 not found. Build or install system package."; exit 1; }

    local token_dir="$TOKENS_DIR/softhsm2"
    mkdir -p "$token_dir/tokens"
    local conf="$token_dir/softhsm2.conf"
    cat > "$conf" <<EOF
directories.tokendir = $token_dir/tokens
objectstore.backend = file
log.level = WARNING
EOF

    if [ -z "$(ls -A "$token_dir/tokens" 2>/dev/null)" ]; then
        echo "Initializing SoftHSM2 token..."
        local util="$BASE_DIR/softhsm2/install/bin/softhsm2-util"
        [ -f "$util" ] || util="softhsm2-util"
        SOFTHSM2_CONF="$conf" "$util" --init-token --slot 0 \
            --label "p11test" --pin 1234 --so-pin 12345678
    fi

    export SOFTHSM2_CONF="$conf"
    MODULE="$so"
    PIN="1234"
}

# Extra: system SoftHSM2 variant
setup_system() {
    local so="/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
    [ -f "$so" ] || { echo "ERROR: System SoftHSM2 not found"; exit 1; }
    local conf="/tmp/p11test-softhsm2.conf"
    [ -f "$conf" ] || bash "$PROJECT_DIR/scripts/setup-softhsm.sh"
    export SOFTHSM2_CONF="$conf"
    MODULE="$so"
    PIN="1234"
}
