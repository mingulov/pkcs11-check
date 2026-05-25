# tpm2-pkcs11 with swtpm + tpm2-abrmd resource manager.

FROM fedora:44

RUN dnf install -y \
    git gcc make autoconf automake autoconf-archive libtool pkgconf-pkg-config \
    sqlite-devel libyaml-devel openssl-devel tpm2-tss-devel \
    tpm2-tools python3-pip python3-cryptography python3-pyyaml \
    python3-pyasn1 python3-pyasn1-modules python3-tpm2-pytss \
    tpm2-abrmd swtpm swtpm-tools \
    python3.14 python3.14-devel \
    dbus-daemon \
    && dnf clean all

ARG TPM2_PKCS11_REF=1.10.0
RUN git clone --depth 1 --branch "$TPM2_PKCS11_REF" \
        https://github.com/tpm2-software/tpm2-pkcs11.git /build/tpm2-pkcs11 && \
    cd /build/tpm2-pkcs11 && \
    git rev-parse HEAD > /tmp/tpm2_pkcs11_revision && \
    python3.14 -m pip install --break-system-packages python-pkcs11 && \
    ./bootstrap && \
    ./configure --prefix=/usr --with-fapi=no PYTHON=/usr/bin/python3.14 && \
    make -j"$(nproc)" && \
    make install && \
    python3.14 -m pip install --break-system-packages ./tools && \
    ldconfig

RUN rpm -q swtpm tpm2-abrmd tpm2-tools tpm2-tss && \
    cat /tmp/tpm2_pkcs11_revision && \
    python3.14 -c 'import importlib.metadata as m; print("python-pkcs11", m.version("python-pkcs11"))' && \
    tpm2_ptool --help >/dev/null

# Test tooling: fault-proxy, pkcs11-provider, p11-kit
COPY docker/fault-proxy.c /tmp/fault-proxy.c
COPY docker/install-test-tools.sh /tmp/install-test-tools.sh
RUN bash /tmp/install-test-tools.sh && rm -f /tmp/install-test-tools.sh

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
RUN uv sync --frozen --python python3.14

# Copy test code (changes frequently, does not invalidate deps cache)
COPY . .

# Flow: swtpm → dbus → tpm2-abrmd → tpm2_ptool init → pkcs11-check
CMD ["bash", "/app/docker/run-with-artifacts.sh", "bash", "/app/docker/tpm2-pkcs11/run-tpm2.sh"]
