#!/bin/bash
# Run pkcs11-check Docker test matrix and collect results.
#
# Usage:
#   bash scripts/run-docker-matrix.sh                    # all targets
#   bash scripts/run-docker-matrix.sh softhsm2 kryoptic  # specific targets
#
# Results are printed as a summary table at the end.

set -euo pipefail

COMPOSE_FILE="docker/docker-compose.test.yml"
RESULTS_DIR="/tmp/pkcs11-check-results"
mkdir -p "$RESULTS_DIR"

# Default targets (stable releases)
DEFAULT_TARGETS=(
    test-softhsm2
    test-kryoptic
    test-opencryptoki
    test-nss
)

# Parse arguments
if [ $# -gt 0 ]; then
    TARGETS=("$@")
    # Prefix with "test-" if not already
    for i in "${!TARGETS[@]}"; do
        [[ "${TARGETS[$i]}" != test-* ]] && TARGETS[$i]="test-${TARGETS[$i]}"
    done
else
    TARGETS=("${DEFAULT_TARGETS[@]}")
fi

echo "=== pkcs11-check Docker Test Matrix ==="
echo "Targets: ${TARGETS[*]}"
echo ""

# Build all targets first
echo "Building images..."
for target in "${TARGETS[@]}"; do
    echo "  Building $target..."
    docker compose -f "$COMPOSE_FILE" build "$target" >/dev/null 2>&1 || {
        echo "  FAILED to build $target"
        echo "BUILD_FAILED" > "$RESULTS_DIR/$target.txt"
        continue
    }
done
echo ""

# Run tests
for target in "${TARGETS[@]}"; do
    result_file="$RESULTS_DIR/$target.txt"

    if [ -f "$result_file" ] && grep -q "BUILD_FAILED" "$result_file"; then
        continue
    fi

    echo "Running $target..."
    docker compose -f "$COMPOSE_FILE" run --rm "$target" 2>&1 | tee "$result_file" | tail -1
    echo ""
done

# Summary
echo ""
echo "=== Results Summary ==="
printf "%-25s %10s %10s %10s %10s %8s\n" "Module" "Passed" "Skipped" "Xfailed" "Failed" "Time"
printf "%-25s %10s %10s %10s %10s %8s\n" "-------" "------" "-------" "-------" "------" "----"

for target in "${TARGETS[@]}"; do
    result_file="$RESULTS_DIR/$target.txt"
    if [ ! -f "$result_file" ]; then
        printf "%-25s %10s\n" "$target" "NOT_RUN"
        continue
    fi

    if grep -q "BUILD_FAILED" "$result_file"; then
        printf "%-25s %10s\n" "$target" "BUILD_FAIL"
        continue
    fi

    # Parse pytest output line
    last_line=$(tail -1 "$result_file")
    passed=$(echo "$last_line" | grep -oP '\d+ passed' | grep -oP '\d+' || echo "?")
    skipped=$(echo "$last_line" | grep -oP '\d+ skipped' | grep -oP '\d+' || echo "0")
    xfailed=$(echo "$last_line" | grep -oP '\d+ xfailed' | grep -oP '\d+' || echo "0")
    failed=$(echo "$last_line" | grep -oP '\d+ failed' | grep -oP '\d+' || echo "0")
    time=$(echo "$last_line" | grep -oP '\d+\.\d+s' | head -1 || echo "?")

    printf "%-25s %10s %10s %10s %10s %8s\n" "$target" "$passed" "$skipped" "$xfailed" "$failed" "$time"
done

echo ""
echo "Full results in: $RESULTS_DIR/"
