#!/usr/bin/env bash
set -euo pipefail

ALL_PROVIDERS=(
    kryoptic-main
    softhsm2-main
    nss-pqc
    opencryptoki-master
    bouncyhsm
    #tpm2
    #kryoptic
    #kryoptic-fips
    #softhsm2
    #nss
    #nss-main
    #opencryptoki
    #pkcs11-mock
    #qryptotoken
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
