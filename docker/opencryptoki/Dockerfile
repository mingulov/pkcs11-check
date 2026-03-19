# OpenCryptoki 3.26 with SWToken — IBM's PKCS#11 implementation
# v3.0 support, software token backed by OpenSSL

FROM fedora:44

RUN dnf install -y \
    opencryptoki opencryptoki-swtok \
    python3 python3-devel \
    gcc openssl-devel git procps-ng \
    && dnf clean all

RUN rpm -q opencryptoki opencryptoki-swtok

# OpenCryptoki runtime directories
RUN mkdir -p /var/lib/opencryptoki/swtok/TOK_OBJ \
    /var/lock/opencryptoki /var/run/opencryptoki && \
    chmod -R 770 /var/lib/opencryptoki /var/lock/opencryptoki /var/run/opencryptoki

# Use only the SW token (slot 3 in default config uses libpkcs11_sw.so)
# Override config to put SW token at slot 0
RUN printf 'version opencryptoki-3.26\n\nslot 0\n{\n    stdll = libpkcs11_sw.so\n    tokversion = 3.12\n}\n' \
    > /etc/opencryptoki/opencryptoki.conf

ENV PKCS11_CHECK_MODULE=/usr/lib64/pkcs11/libopencryptoki.so
ENV PKCS11_CHECK_PIN=1234

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY . .
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_PYTHON_PKCS11=0.0
RUN uv sync --frozen --python /usr/bin/python3

# Add root to pkcs11 group so we can talk to pkcsslotd
RUN usermod -a -G pkcs11 root

CMD ["bash", "/app/docker/run-with-artifacts.sh", "bash", "/app/docker/opencryptoki/run-opencryptoki.sh"]
