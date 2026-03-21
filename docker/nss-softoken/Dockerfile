# NSS softoken — stable (Fedora 43, latest release)
# Well-tested NSS with v3.0 support
FROM fedora:43

RUN dnf install -y \
    nss nss-tools nss-softokn \
    python3.12 python3.12-devel \
    gcc openssl-devel git \
    && dnf clean all

RUN rpm -q nss nss-softokn

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV NSS_DB_DIR=/var/lib/nss
RUN mkdir -p $NSS_DB_DIR && \
    certutil -d sql:$NSS_DB_DIR -N --empty-password

RUN find /usr/lib64 /usr/lib -name "libsoftokn3.so" 2>/dev/null | head -1 > /tmp/module_path
ENV PKCS11_CHECK_SLOT=1

WORKDIR /app
# Install deps first (cached unless pyproject.toml/uv.lock/python-pkcs11 change)
COPY pyproject.toml uv.lock ./
COPY python-pkcs11/ python-pkcs11/
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_PYTHON_PKCS11=0.0
RUN uv python pin 3.12 && uv sync --frozen

# Copy test code (changes frequently, does not invalidate deps cache)
COPY . .

CMD ["bash", "/app/docker/run-with-artifacts.sh", "sh", "-c", "echo 'NSS (stable):' && rpm -q nss && export PKCS11_CHECK_MODULE=$(cat /tmp/module_path) && bash /app/docker/run-pkcs11-check.sh"]
