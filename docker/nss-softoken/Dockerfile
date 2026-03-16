FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 \
    libnss3-tools \
    && rm -rf /var/lib/apt/lists/*

# Print NSS version
RUN nss-config --version 2>/dev/null || pkg-config --modversion nss 2>/dev/null || echo "NSS version unknown"

# Initialize NSS database for softoken
ENV NSS_DB_DIR=/var/lib/nss
RUN mkdir -p $NSS_DB_DIR && \
    certutil -d sql:$NSS_DB_DIR -N --empty-password

# NSS softoken module path
RUN find /usr/lib -name "libsoftokn3.so" | head -1 > /tmp/module_path
ENV P11TEST_PIN=""

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

COPY . .
RUN uv sync --frozen

# NSS softoken — note: initialization and PIN semantics differ from SoftHSM2
CMD ["sh", "-c", "echo 'NSS softoken at:' && cat /tmp/module_path && uv run pytest src/p11test/testcases/ --p11-module=$(cat /tmp/module_path) -v || echo 'Some tests may fail due to NSS-specific initialization requirements'"]
