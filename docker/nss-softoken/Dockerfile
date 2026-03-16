FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 \
    libnss3-tools \
    && rm -rf /var/lib/apt/lists/*

# Initialize NSS database for softoken
ENV NSS_DB_DIR=/var/lib/nss
RUN mkdir -p $NSS_DB_DIR && \
    certutil -d sql:$NSS_DB_DIR -N --empty-password && \
    modutil -dbdir sql:$NSS_DB_DIR -changepw "NSS Certificate DB" -newpwfile /dev/null 2>/dev/null || true

# NSS softoken module path
RUN find /usr/lib -name "libsoftokn3.so" | head -1 > /tmp/module_path
ENV P11TEST_PIN=""

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

COPY . .
RUN uv sync --frozen

# NSS softoken has different initialization requirements
# May need additional configuration for full test compatibility
CMD ["sh", "-c", "uv run pytest src/p11test/testcases/ --p11-module=$(cat /tmp/module_path) -v"]
