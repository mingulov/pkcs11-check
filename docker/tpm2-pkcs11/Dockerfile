# tpm2-pkcs11 with swtpm + tpm2-abrmd resource manager
# The resource manager solves the "out of memory for object contexts" issue

FROM fedora:44

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
ENV PKCS11_CHECK_PIN=1234

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
# Install deps first (cached unless pyproject.toml/uv.lock change)
COPY pyproject.toml uv.lock README.md ./
COPY src/pkcs11_check/__init__.py src/pkcs11_check/__init__.py
COPY third_party/ third_party/
RUN uv python pin 3.12 && uv sync --frozen

# Copy test code (changes frequently, does not invalidate deps cache)
COPY . .

# Flow: swtpm → dbus → tpm2-abrmd → tpm2_ptool init → pkcs11-check
CMD ["bash", "/app/docker/run-with-artifacts.sh", "bash", "/app/docker/tpm2-pkcs11/run-tpm2.sh"]
