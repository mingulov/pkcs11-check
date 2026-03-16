FROM rust:1.82-slim AS kryoptic-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build Kryoptic from source
RUN git clone --depth 1 https://github.com/latchset/kryoptic.git /build/kryoptic
WORKDIR /build/kryoptic
RUN cargo build --release --features fips
# The output is libkryoptic_pkcs11.so

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy Kryoptic module from builder
COPY --from=kryoptic-builder /build/kryoptic/target/release/libkryoptic_pkcs11.so /usr/lib/

# Kryoptic configuration
# See: https://github.com/latchset/kryoptic/blob/main/README.md
ENV KRYOPTIC_CONF=/etc/kryoptic.conf
RUN echo '[token]\nlabel = "p11test"\npin = "1234"\nso_pin = "12345678"\n' > $KRYOPTIC_CONF

ENV P11TEST_MODULE=/usr/lib/libkryoptic_pkcs11.so
ENV P11TEST_PIN=1234

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

COPY . .
RUN uv sync --frozen

# Run tests — Kryoptic in FIPS mode exposes v3.2 interfaces
CMD ["uv", "run", "pytest", "src/p11test/testcases/", "--p11-module=/usr/lib/libkryoptic_pkcs11.so", "--p11-pin=1234", "-v"]
