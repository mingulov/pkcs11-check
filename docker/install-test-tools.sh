#!/usr/bin/env bash
# Install shared test tooling (fault-proxy, pkcs11-provider, p11-kit)
# for pkcs11-check Docker images. Handles Debian (apt) and Fedora (dnf).
set -euo pipefail

# --- Detect distro ---
if command -v apt-get &>/dev/null; then
    DISTRO=debian
elif command -v dnf &>/dev/null; then
    DISTRO=fedora
else
    echo "WARNING: Unknown distro, skipping test tool install" >&2
    exit 0
fi

# --- p11-kit ---
case $DISTRO in
    debian) apt-get update && apt-get install -y --no-install-recommends \
                p11-kit p11-kit-modules ;;
    fedora) dnf install -y p11-kit ;;
esac

# --- pkcs11-provider (OpenSSL 3.x PKCS#11 provider) ---
case $DISTRO in
    debian) apt-get install -y --no-install-recommends pkcs11-provider ;;
    fedora) dnf install -y pkcs11-provider || true ;;
esac

# --- fault-proxy (compile from bundled source) ---
if [ -f /tmp/fault-proxy.c ]; then
    mkdir -p /usr/lib/pkcs11
    gcc -shared -fPIC -o /usr/lib/pkcs11/fault-proxy.so /tmp/fault-proxy.c -ldl
    rm -f /tmp/fault-proxy.c
    echo "fault-proxy.so installed to /usr/lib/pkcs11/"
fi

# --- Cleanup ---
case $DISTRO in
    debian) rm -rf /var/lib/apt/lists/* ;;
    fedora) dnf clean all ;;
esac
