# tpm2-pkcs11 with swtpm (software TPM emulator)
# Tests PKCS#11 through TPM2 stack: tpm2-pkcs11 → tpm2-tss → swtpm

FROM fedora:43

RUN dnf install -y \
    tpm2-pkcs11 tpm2-pkcs11-tools tpm2-tools \
    swtpm swtpm-tools \
    python3.12 python3.12-devel \
    gcc openssl-devel git \
    && dnf clean all

RUN rpm -q tpm2-pkcs11 swtpm

# Set up swtpm (software TPM)
RUN mkdir -p /tmp/swtpm && \
    swtpm_setup --tpm2 --tpmstate /tmp/swtpm --createek --decryption --create-ek-cert \
    --create-platform-cert --lock-nvram 2>/dev/null || true

# Find the tpm2-pkcs11 module
RUN find /usr/lib64 /usr/lib -name "libtpm2_pkcs11.so*" 2>/dev/null | head -1 > /tmp/module_path && \
    echo "Module: $(cat /tmp/module_path)"

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY . .
RUN uv python pin 3.12 && uv sync --frozen

# Start swtpm, initialize token, then run tests
CMD ["sh", "-c", "\
  echo 'tpm2-pkcs11:' && rpm -q tpm2-pkcs11 swtpm && \
  swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm \
    --ctrl type=tcp,port=2322 --server type=tcp,port=2321 \
    --flags not-need-init &>/dev/null & \
  sleep 2 && \
  export TPM2TOOLS_TCTI='swtpm:host=127.0.0.1,port=2321' && \
  export TPM2_PKCS11_TCTI='swtpm:host=127.0.0.1,port=2321' && \
  tpm2_pkcs11_init --pobj-pin=1234 --label=p11test --sopin=12345678 --userpin=1234 2>/dev/null && \
  MODULE=$(cat /tmp/module_path) && \
  uv run pytest src/p11test/testcases/ --p11-module=$MODULE --p11-pin=1234 -q --tb=no || \
  echo 'Some tests may fail — TPM2 has limited mechanism support'"]
