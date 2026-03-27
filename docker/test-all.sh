#!/usr/bin/env bash
set -euo pipefail

ALL_PROVIDERS=(
    kryoptic
    kryoptic-fips
    kryoptic-main
    softhsm2
    softhsm2-main
    nss
    nss-pqc
    nss-main
    opencryptoki
    opencryptoki-master
    tpm2
    bouncyhsm
    pkcs11-mock
    qryptotoken
)

providers=("$@")
if [[ ${#providers[@]} -eq 0 ]]; then
    providers=("${ALL_PROVIDERS[@]}")
fi

for provider in "${providers[@]}"; do
    echo ""
    echo "================================================================"
    echo "  $provider"
    echo "================================================================"
    bash docker/test.sh "$provider" || true
done
