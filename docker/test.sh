#!/usr/bin/env bash

# Host-side entrypoint for Docker-based provider testing.
# Usage: ./docker/test.sh <provider> [--timeout <seconds>] [--results-dir <dir>] [--debug] [--build] -- [pytest args]
#
# Sets up artifacts directory, launches container, and collects results.

set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 <provider> [--timeout <seconds>] [--results-dir <dir>] [--debug] [--build] -- [pytest args]

Options:
    --timeout <seconds>  Max runtime in seconds (default: 1200)
    --results-dir <dir>  Directory for artifacts (default: artifacts/<provider>/)
    --debug             Enable debug output
    --build             Force Docker image rebuild (no cache)
    --                  Separator for pytest arguments

Examples:
    $0 softhsm2
    $0 kryoptic --timeout 1800 -- src/pkcs11_check/testcases/test_digest.py -v
    $0 opencryptoki --results-dir ./my-results
    $0 kryoptic-main --build -- src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py -v
EOF
    exit 1
}

# Initialize variables
TIMEOUT=1200
RESULTS_DIR=""
DEBUG=false
BUILD_ARG=""
declare -a PYTEST_ARGS=()

# Parse arguments
[[ $# -eq 0 ]] && usage

provider="$1"
shift

while [[ $# -gt 0 ]]; do
    case "$1" in
        --timeout)
            [[ -n "${2:-}" ]] || usage
            TIMEOUT="$2"
            shift 2
            ;;
        --results-dir)
            [[ -n "${2:-}" ]] || usage
            RESULTS_DIR="$2"
            shift 2
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        --build)
            BUILD_ARG="--build"
            shift
            ;;
        --)
            shift
            PYTEST_ARGS=("$@")
            break
            ;;
        -*)
            echo "Unknown option: $1" >&2
            usage
            ;;
        *)
            # Treat as provider if first arg, else pytest argument
            if [[ -z "$provider" ]]; then
                provider="$1"
                shift
            else
                break
            fi
            ;;
    esac
done

# Determine results directory
if [[ -z "$RESULTS_DIR" ]]; then
    RESULTS_DIR="artifacts/${provider}"
fi
mkdir -p "$RESULTS_DIR"

# Map provider names to Docker Compose service names
case "$provider" in
    softhsm2|test-softhsm2)
        service_name="test-softhsm2"
        ;;
    softhsm2-main|test-softhsm2-main)
        service_name="test-softhsm2-main"
        ;;
    kryoptic|test-kryoptic)
        service_name="test-kryoptic"
        ;;
    kryoptic-main|test-kryoptic-main)
        service_name="test-kryoptic-main"
        ;;
    kryoptic-fips|test-kryoptic-fips)
        service_name="test-kryoptic-fips"
        ;;
    opencryptoki|test-opencryptoki)
        service_name="test-opencryptoki"
        ;;
    nss|test-nss)
        service_name="test-nss"
        ;;
    nss-pqc|test-nss-pqc)
        service_name="test-nss-pqc"
        ;;
    tpm2|test-tpm2)
        service_name="test-tpm2"
        ;;
    bouncyhsm|test-bouncyhsm)
        service_name="test-bouncyhsm"
        ;;
    pkcs11-mock|test-pkcs11-mock)
        service_name="test-pkcs11-mock"
        ;;
    qryptotoken|test-qryptotoken)
        service_name="test-qryptotoken"
        ;;
    *)
        echo "Unknown provider: $provider" >&2
        usage
        ;;
esac

# Find compose file
COMPOSE_FILE="docker/docker-compose.test.yml"
if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo "Compose file not found: $COMPOSE_FILE" >&2
    exit 1
fi

# Export timeout for docker-compose to pick up
export PKCS11_CHECK_TIMEOUT="$TIMEOUT"

# Debug output
if [[ "$DEBUG" == "true" ]]; then
    echo "Provider: $provider"
    echo "Service: $service_name"
    echo "Results: $RESULTS_DIR"
    echo "Timeout: $TIMEOUT"
    echo "Build: $BUILD_ARG"
fi

# Run tests with artifacts
echo "Running tests for $provider (timeout: ${TIMEOUT}s)..."
if [[ ${#PYTEST_ARGS[@]} -gt 0 ]]; then
    docker compose -f "$COMPOSE_FILE" run ${BUILD_ARG} --rm "${service_name}" "${PYTEST_ARGS[@]}" 2>&1 | tee "${RESULTS_DIR}/console.log" || true
else
    docker compose -f "$COMPOSE_FILE" run ${BUILD_ARG} --rm "${service_name}" 2>&1 | tee "${RESULTS_DIR}/console.log" || true
fi

# Check for artifacts
echo ""
echo "Checking for artifacts in container..."
docker compose -f "$COMPOSE_FILE" run --rm "${service_name}" ls -la /artifacts/ 2>/dev/null || echo "No artifacts in /artifacts/"

# Copy artifacts from container if they exist
echo ""
echo "Copying artifacts from container..."
docker cp "$(docker compose -f "$COMPOSE_FILE" ps -q ${service_name} 2>/dev/null || echo ''):/artifacts/." "$RESULTS_DIR/" 2>/dev/null || echo "No artifacts to copy"

echo ""
echo "Results saved to: $RESULTS_DIR"

# Quick summary
passed=$(grep -c '"outcome": "passed"' "${RESULTS_DIR}/results.json" 2>/dev/null || echo "0")
failed=$(grep -c '"outcome": "failed"' "${RESULTS_DIR}/results.json" 2>/dev/null || echo "0")
total=$(grep -c '"nodeid"' "${RESULTS_DIR}/results.json" 2>/dev/null || echo "0")

echo "Summary: ${passed:-0} passed, ${failed:-0} failed, ${total:-0} total"