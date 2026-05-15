#!/usr/bin/env bash
# swtpm — software TPM emulator (build from source)
# Latest release: v0.10.1 (requires libtpms 0.10+)
# Used by tpm2-swtpm provider for testing without hardware TPM.

PROVIDER_NAME="swtpm"
LIBTPMS_VERSION="v0.10.2"
SWTPM_VERSION="v0.10.1"

build() {
    echo "=== Building libtpms + swtpm from source ==="

    local base="$BASE_DIR/swtpm"
    local prefix="$base/install"
    mkdir -p "$prefix"

    # Build libtpms first
    echo "--- Building libtpms ($LIBTPMS_VERSION) ---"
    local libtpms_src="$base/libtpms-src"
    if [ ! -d "$libtpms_src" ]; then
        git clone --depth 1 --branch "$LIBTPMS_VERSION" https://github.com/stefanberger/libtpms.git "$libtpms_src"
    fi
    cd "$libtpms_src"
    [ -f configure ] || ./autogen.sh --with-tpm2 --with-openssl --prefix="$prefix"
    [ -f Makefile ] || ./configure --with-tpm2 --with-openssl --prefix="$prefix"
    make -j"$(nproc)"
    make install
    echo "libtpms installed to $prefix"

    # Build swtpm
    echo "--- Building swtpm ($SWTPM_VERSION) ---"
    local swtpm_src="$base/swtpm-src"
    if [ ! -d "$swtpm_src" ]; then
        git clone --depth 1 --branch "$SWTPM_VERSION" https://github.com/stefanberger/swtpm.git "$swtpm_src"
    fi
    cd "$swtpm_src"
    export PKG_CONFIG_PATH="$prefix/lib/pkgconfig:$prefix/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"
    export LD_LIBRARY_PATH="$prefix/lib:$prefix/lib64:${LD_LIBRARY_PATH:-}"
    [ -f configure ] || ./autogen.sh
    [ -f Makefile ] || ./configure --prefix="$prefix" --with-openssl
    make -j"$(nproc)"
    make install

    echo ""
    echo "Built: $prefix/bin/swtpm"
    "$prefix/bin/swtpm" --version
}

setup() {
    echo "swtpm is a dependency for tpm2-swtpm, not a PKCS#11 provider."
    echo "Use: bash local-builds/test.sh tpm2-swtpm"
    exit 1
}
