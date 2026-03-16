#!/bin/bash
# Set up SoftHSM2 for p11test development and testing.
# Creates a temporary token directory and initializes a test token.
#
# Usage:
#   source scripts/setup-softhsm.sh    # sets env vars in current shell
#   bash scripts/setup-softhsm.sh      # prints env vars to export
set -euo pipefail

TOKEN_DIR="${P11TEST_TOKEN_DIR:-/tmp/p11test-tokens}"
CONF_FILE="${SOFTHSM2_CONF:-/tmp/p11test-softhsm2.conf}"
PIN="${P11TEST_PIN:-1234}"
SO_PIN="${P11TEST_SO_PIN:-12345678}"
LABEL="${P11TEST_LABEL:-p11test}"

mkdir -p "$TOKEN_DIR"

cat > "$CONF_FILE" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = WARNING
EOF

export SOFTHSM2_CONF="$CONF_FILE"

# Initialize token (ignore if already exists)
softhsm2-util --init-token --slot 0 --label "$LABEL" \
    --pin "$PIN" --so-pin "$SO_PIN" 2>/dev/null || true

# Find module path
MODULE=""
for path in \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib64/softhsm/libsofthsm2.so \
    /usr/lib/softhsm/libsofthsm2.so \
    /opt/homebrew/lib/softhsm/libsofthsm2.so \
    /usr/local/lib/softhsm/libsofthsm2.so; do
    if [ -f "$path" ]; then
        MODULE="$path"
        break
    fi
done

if [ -z "$MODULE" ]; then
    echo "ERROR: libsofthsm2.so not found" >&2
    exit 1
fi

echo "# SoftHSM2 configured for p11test"
echo "export SOFTHSM2_CONF=$CONF_FILE"
echo "export P11TEST_MODULE=$MODULE"
echo "export P11TEST_PIN=$PIN"
echo "export P11TEST_SLOT=0"
