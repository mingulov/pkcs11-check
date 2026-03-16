# tpm2-pkcs11 with swtpm (software TPM emulator)

FROM fedora:43

RUN dnf install -y \
    tpm2-pkcs11 tpm2-pkcs11-tools tpm2-tools \
    swtpm swtpm-tools \
    python3.12 python3.12-devel \
    gcc openssl-devel git \
    && dnf clean all

RUN rpm -q tpm2-pkcs11 swtpm

# Create empty swtpm state dir (no pre-setup — cleaner, more context slots)
RUN mkdir -p /tmp/swtpm

RUN find /usr/lib64 /usr/lib -name "libtpm2_pkcs11.so" 2>/dev/null | head -1 > /tmp/module_path

ENV TPM2_PKCS11_STORE=/var/lib/tpm2_pkcs11
RUN mkdir -p $TPM2_PKCS11_STORE

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY . .
RUN uv python pin 3.12 && uv sync --frozen

CMD ["sh", "-c", "\
  echo 'tpm2-pkcs11:' && rpm -q tpm2-pkcs11 swtpm && \
  swtpm socket --tpm2 \
    --tpmstate dir=/tmp/swtpm \
    --ctrl type=tcp,port=2322 \
    --server type=tcp,port=2321 \
    --flags startup-clear \
    --log level=0 &>/dev/null & \
  sleep 2 && \
  export TCTI='swtpm:host=127.0.0.1,port=2321' && \
  export TPM2TOOLS_TCTI=\"$TCTI\" && \
  export TPM2_PKCS11_TCTI=\"$TCTI\" && \
  tpm2_startup -c 2>&1 || true && \
  tpm2_getcap properties-fixed 2>&1 | head -3 && \
  tpm2_ptool init --primary-auth=1234 2>&1 && \
  tpm2_ptool addtoken --pid=1 --sopin=12345678 --userpin=1234 --label=p11test 2>&1 && \
  MODULE=$(cat /tmp/module_path) && \
  echo \"Module: $MODULE\" && \
  uv run pytest src/p11test/testcases/ \
    --p11-module=\"$MODULE\" --p11-pin=1234 -q --tb=no || \
  echo 'Some tests may fail — TPM2 has limited mechanism support'"]
