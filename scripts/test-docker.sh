#!/bin/bash
# Run pkcs11-check against all Docker-based PKCS#11 modules.
#
# Usage:
#   ./scripts/test-docker.sh                    # run all
#   ./scripts/test-docker.sh softhsm2           # run one
#   ./scripts/test-docker.sh kryoptic softhsm2  # run selected
set -euo pipefail

COMPOSE_FILE="docker/docker-compose.test.yml"

if [ $# -eq 0 ]; then
    # Run all services
    echo "=== Running all PKCS#11 module tests ==="
    docker compose -f "$COMPOSE_FILE" build
    docker compose -f "$COMPOSE_FILE" up --abort-on-container-exit --exit-code-from test-softhsm2
else
    # Run specified services
    for service in "$@"; do
        echo "=== Testing: test-${service} ==="
        docker compose -f "$COMPOSE_FILE" build "test-${service}"
        docker compose -f "$COMPOSE_FILE" run --rm "test-${service}"
    done
fi
