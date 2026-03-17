#!/usr/bin/env bash
# Cross-module differential: run tests on SoftHSM2 and Kryoptic,
# then compare outcomes to flag behavioral differences.
#
# Usage: bash scripts/cross-module-diff.sh
#
# Requires Docker for Kryoptic, local SoftHSM2 for fast local run.

set -euo pipefail

RESULTS_DIR="results"
mkdir -p "$RESULTS_DIR"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)

echo "=== Running SoftHSM2 (local) ==="
SOFTHSM2_CONF=/tmp/p11test-softhsm2.conf uv run pytest src/p11test/testcases/ \
  --p11-module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --p11-pin=1234 \
  --junitxml="$RESULTS_DIR/softhsm2-${TIMESTAMP}.xml" \
  -q --benchmark-disable --timeout=300 2>&1 | tail -3

echo ""
echo "=== Running Kryoptic (Docker) ==="
docker compose -f docker/docker-compose.test.yml build test-kryoptic 2>&1 | tail -1
docker compose -f docker/docker-compose.test.yml run --rm \
  -e PYTEST_ADDOPTS="--junitxml=/tmp/results.xml --timeout=300" \
  test-kryoptic 2>&1 | tail -3

# Note: Kryoptic results stay inside the container.
# To get them out, we'd need a volume mount. For now, use the matrix script
# with the local SoftHSM2 results and Docker logs.

echo ""
echo "=== Differential Analysis ==="
echo "SoftHSM2 results: $RESULTS_DIR/softhsm2-${TIMESTAMP}.xml"
echo ""
echo "To compare, run both with --junitxml and:"
echo "  uv run python scripts/mechanism-matrix.py results/softhsm2-*.xml results/kryoptic-*.xml"
