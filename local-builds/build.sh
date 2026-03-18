#!/usr/bin/env bash
# Build one or all soft tokens locally.
# Usage: bash local-builds/build.sh [target|all]
#
# For per-token options (branch, custom OpenSSL, etc.),
# use the individual build-<token>.sh scripts directly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "${1:-help}" in
    openssl)      bash "$SCRIPT_DIR/build-openssl.sh" "${@:2}" ;;
    kryoptic)     bash "$SCRIPT_DIR/build-kryoptic.sh" "${@:2}" ;;
    softhsm2)     bash "$SCRIPT_DIR/build-softhsm2.sh" "${@:2}" ;;
    opencryptoki) bash "$SCRIPT_DIR/build-opencryptoki.sh" "${@:2}" ;;
    tpm2-pkcs11)  bash "$SCRIPT_DIR/build-tpm2-pkcs11.sh" "${@:2}" ;;
    pkcs11-mock)  bash "$SCRIPT_DIR/build-pkcs11-mock.sh" "${@:2}" ;;
    qryptotoken)  bash "$SCRIPT_DIR/build-qryptotoken.sh" "${@:2}" ;;
    bouncyhsm)    bash "$SCRIPT_DIR/build-bouncyhsm.sh" "${@:2}" ;;
    all)
        bash "$SCRIPT_DIR/build-openssl.sh"
        bash "$SCRIPT_DIR/build-kryoptic.sh"
        bash "$SCRIPT_DIR/build-softhsm2.sh"
        bash "$SCRIPT_DIR/build-pkcs11-mock.sh"
        bash "$SCRIPT_DIR/build-qryptotoken.sh"
        echo ""
        echo "Skipped (need extra deps):"
        echo "  opencryptoki — needs pkcsslotd, special groups"
        echo "  tpm2-pkcs11  — needs swtpm, tpm2-abrmd"
        echo "  bouncyhsm    — needs .NET SDK"
        ;;
    *)
        echo "Usage: $0 <target> [args...]"
        echo ""
        echo "Targets:"
        echo "  openssl       — OpenSSL (dependency for others)"
        echo "  kryoptic      — Kryoptic (Rust, v3.2)"
        echo "  softhsm2      — SoftHSM2 (C++, v2.40)"
        echo "  opencryptoki  — OpenCryptoki (C, v3.0)"
        echo "  tpm2-pkcs11   — tpm2-pkcs11 + swtpm"
        echo "  pkcs11-mock   — pkcs11-mock (C, v3.1 stub)"
        echo "  qryptotoken   — qryptotoken (Rust, PQC)"
        echo "  bouncyhsm     — BouncyHSM (.NET)"
        echo "  all           — build all (skips those needing extra deps)"
        echo ""
        echo "Individual scripts accept extra args (e.g. branch):"
        echo "  bash local-builds/build-kryoptic.sh main"
        echo "  bash local-builds/build-softhsm2.sh master"
        echo "  OPENSSL_DIR=\$PWD/local-builds/openssl/install bash local-builds/build-softhsm2.sh"
        exit 1
        ;;
esac
