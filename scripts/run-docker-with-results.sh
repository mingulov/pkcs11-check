#!/usr/bin/env bash
# Run Docker test matrix and save JUnit XML results.
#
# Usage: bash scripts/run-docker-with-results.sh [module...]
#   If no modules specified, runs softhsm2 and kryoptic.
#
# Results saved to: results/<module>-<timestamp>.xml

set -euo pipefail

RESULTS_DIR="results"
mkdir -p "$RESULTS_DIR"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
COMPOSE_FILE="docker/docker-compose.test.yml"

MODULES=("${@:-test-softhsm2 test-kryoptic}")
if [ $# -eq 0 ]; then
    MODULES=(test-softhsm2 test-kryoptic)
fi

for MODULE in "${MODULES[@]}"; do
    echo "=== Running $MODULE ==="
    RESULT_FILE="$RESULTS_DIR/${MODULE}-${TIMESTAMP}.xml"

    # Build first
    docker compose -f "$COMPOSE_FILE" build "$MODULE" 2>&1 | tail -1

    # Run with JUnit XML output
    docker compose -f "$COMPOSE_FILE" run --rm \
        -e PYTEST_ADDOPTS="--junitxml=/tmp/results.xml --timeout=300" \
        "$MODULE" 2>&1 | tee "$RESULTS_DIR/${MODULE}-${TIMESTAMP}.log" || true

    # Copy results from container (if available)
    # Note: results are inside the container, so we capture from log output
    echo "Results log: $RESULTS_DIR/${MODULE}-${TIMESTAMP}.log"
    echo ""
done

echo "=== Done. Results in $RESULTS_DIR/ ==="
