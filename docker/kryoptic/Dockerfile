# Stage 1: Build Kryoptic v1.5.0
FROM rust:latest AS kryoptic-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git pkg-config libssl-dev clang make \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --branch v1.5.0 --depth 1 https://github.com/latchset/kryoptic.git /build/kryoptic
WORKDIR /build/kryoptic
RUN cargo build --release

# Stage 2: Runtime with tests
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 git gcc python3-dev libssl-dev opensc \
    && rm -rf /var/lib/apt/lists/*

COPY --from=kryoptic-builder /build/kryoptic/target/release/libkryoptic_pkcs11.so /usr/lib/

# Create Kryoptic config with SQLite backend
RUN mkdir -p /var/lib/kryoptic /etc/kryoptic
RUN printf '[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "/var/lib/kryoptic/token.sql"\n' \
    > /etc/kryoptic/token.conf
ENV KRYOPTIC_CONF=/etc/kryoptic/token.conf

# Initialize token using pkcs11-tool (from opensc package)
RUN pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
    --init-token --label "pkcs11-check" --so-pin 12345678 \
    && pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
    --init-pin --pin 1234 --so-pin 12345678

ENV P11TEST_MODULE=/usr/lib/libkryoptic_pkcs11.so
ENV P11TEST_PIN=1234

WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY . .
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_PYTHON_PKCS11=0.0
RUN uv sync --frozen

CMD ["uv", "run", "pytest", "src/pkcs11_check/testcases/", "--p11-module=/usr/lib/libkryoptic_pkcs11.so", "--p11-pin=1234", "-q"]
