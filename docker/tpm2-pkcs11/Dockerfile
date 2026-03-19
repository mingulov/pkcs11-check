# tpm2-pkcs11 with swtpm + tpm2-abrmd resource manager
# The resource manager solves the "out of memory for object contexts" issue

FROM fedora:43

RUN dnf install -y \
    tpm2-pkcs11 tpm2-pkcs11-tools tpm2-tools \
    tpm2-abrmd swtpm swtpm-tools \
    python3.12 python3.12-devel \
    gcc openssl-devel git dbus-daemon \
    && dnf clean all

RUN rpm -q tpm2-pkcs11 swtpm tpm2-abrmd

RUN mkdir -p /tmp/swtpm /var/lib/tpm2_pkcs11 /run/dbus

RUN find /usr/lib64 /usr/lib -name "libtpm2_pkcs11.so" 2>/dev/null | head -1 > /tmp/module_path

ENV TPM2_PKCS11_STORE=/var/lib/tpm2_pkcs11

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY . .
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_PYTHON_PKCS11=0.0
RUN uv python pin 3.12 && uv sync --frozen

# Flow: swtpm → dbus → tpm2-abrmd → tpm2_ptool init → pytest
CMD ["sh", "-c", "\
  echo 'tpm2-pkcs11:' && rpm -q tpm2-pkcs11 swtpm tpm2-abrmd && \
  swtpm socket --tpm2 \
    --tpmstate dir=/tmp/swtpm \
    --ctrl type=tcp,port=2322 \
    --server type=tcp,port=2321 \
    --flags startup-clear \
    --log level=0 &>/dev/null & \
  sleep 1 && \
  dbus-daemon --system --fork 2>/dev/null && \
  tpm2-abrmd --tcti=swtpm:host=127.0.0.1,port=2321 --allow-root &>/dev/null & \
  sleep 2 && \
  export TPM2TOOLS_TCTI='tabrmd:bus_type=system' && \
  export TPM2_PKCS11_TCTI='tabrmd:bus_type=system' && \
  tpm2_getcap properties-fixed 2>&1 | head -3 && \
  tpm2_ptool init 2>&1 && \
  tpm2_ptool addtoken --pid=1 --sopin=12345678 --userpin=1234 --label=pkcs11-check 2>&1 && \
  MODULE=$(cat /tmp/module_path) && \
  echo \"Module: $MODULE\" && \
  uv run pytest src/pkcs11_check/testcases/ \
    --p11-module=\"$MODULE\" --p11-pin=1234 -q --tb=no || \
  echo 'Some tests may fail — TPM2 has limited mechanism support'"]
