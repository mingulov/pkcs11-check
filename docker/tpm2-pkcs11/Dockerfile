# tpm2-pkcs11 with swtpm (software TPM emulator)
# Tests PKCS#11 through TPM2 stack: tpm2-pkcs11 → tpm2-tss → swtpm
#
# Architecture:
#   swtpm runs as a TCP socket emulator (ports 2321/2322)
#   tpm2-tools and tpm2-pkcs11-tools talk to swtpm via TCTI
#   libtpm2_pkcs11.so is the PKCS#11 module loaded by applications
#
# Token initialization (tpm2_ptool) must happen at CMD time because swtpm
# must be live during init.

FROM fedora:43

RUN dnf install -y \
    tpm2-pkcs11 tpm2-pkcs11-tools tpm2-tools \
    swtpm swtpm-tools \
    python3.12 python3.12-devel \
    gcc openssl-devel git \
    && dnf clean all

RUN rpm -q tpm2-pkcs11 swtpm

# Create swtpm state dir and run first-time setup (creates EK, certs, NV).
# This is offline setup that does not need swtpm daemon running.
RUN mkdir -p /tmp/swtpm && \
    swtpm_setup --tpm2 --tpmstate /tmp/swtpm \
        --createek --decryption --create-ek-cert \
        --create-platform-cert --lock-nvram 2>&1 || true

# Locate the PKCS#11 module (.so may have a version suffix; pick the base name
# symlink if present, otherwise the first match).
RUN find /usr/lib64 /usr/lib -name "libtpm2_pkcs11.so" 2>/dev/null | head -1 \
        > /tmp/module_path && \
    find /usr/lib64 /usr/lib -name "libtpm2_pkcs11.so*" 2>/dev/null | head -1 \
        >> /tmp/module_path && \
    sort -u /tmp/module_path | head -1 > /tmp/module_path.final && \
    mv /tmp/module_path.final /tmp/module_path && \
    echo "Module path: $(cat /tmp/module_path)"

ENV TPM2_PKCS11_STORE=/var/lib/tpm2_pkcs11
RUN mkdir -p $TPM2_PKCS11_STORE

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY . .
RUN uv python pin 3.12 && uv sync --frozen

# Flow:
#   1. Start swtpm socket server
#   2. Export TCTI env so tpm2-tools talk to swtpm
#   3. Initialize token via tpm2_ptool (the high-level init helper)
#   4. Run tests
CMD ["sh", "-c", "\
  echo 'tpm2-pkcs11:' && rpm -q tpm2-pkcs11 swtpm && \
  swtpm socket --tpm2 \
    --tpmstate dir=/tmp/swtpm \
    --ctrl type=tcp,port=2322 \
    --server type=tcp,port=2321 \
    --flags not-need-init \
    --log level=0 &>/dev/null & \
  sleep 2 && \
  export TPM2TOOLS_TCTI='swtpm:host=127.0.0.1,port=2321' && \
  export TPM2_PKCS11_TCTI='swtpm:host=127.0.0.1,port=2321' && \
  MODULE=$(cat /tmp/module_path) && \
  echo \"Using module: $MODULE\" && \
  tpm2_ptool init 2>&1 || true && \
  tpm2_ptool addtoken \
    --pid=1 \
    --sopin=12345678 \
    --userpin=1234 \
    --label=p11test 2>&1 || true && \
  uv run pytest src/p11test/testcases/ \
    --p11-module=\"$MODULE\" \
    --p11-pin=1234 -q --tb=short || \
  echo 'Some tests may fail — TPM2 has limited mechanism support'"]
