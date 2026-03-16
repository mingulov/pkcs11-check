# Stage 1: Build Kryoptic v1.5.0
FROM rust:1.82-slim AS kryoptic-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --branch v1.5.0 --depth 1 https://github.com/latchset/kryoptic.git /build/kryoptic
WORKDIR /build/kryoptic
RUN cargo build --release
# Output: target/release/libkryoptic_pkcs11.so

# Stage 2: Python deps (cached)
FROM python:3.12-slim AS deps

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

# Stage 3: Runtime
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=kryoptic-builder /build/kryoptic/target/release/libkryoptic_pkcs11.so /usr/lib/

RUN mkdir -p /var/lib/kryoptic /etc/kryoptic && \
    printf '[token]\nlabel = "p11test"\npin = "1234"\nso-pin = "12345678"\nstorage = "/var/lib/kryoptic"\n' \
    > /etc/kryoptic/token.conf
ENV KRYOPTIC_CONF=/etc/kryoptic/token.conf
ENV P11TEST_MODULE=/usr/lib/libkryoptic_pkcs11.so
ENV P11TEST_PIN=1234

WORKDIR /app

COPY --from=deps /usr/local/bin/uv /usr/local/bin/uv
COPY --from=deps /app/.venv /app/.venv

COPY . .
RUN uv sync --frozen

CMD ["uv", "run", "pytest", "src/p11test/testcases/", "--p11-module=/usr/lib/libkryoptic_pkcs11.so", "--p11-pin=1234", "-v"]
