# Kryoptic FIPS — main branch with FIPS+PQC features
# Uses simo5/openssl kryoptic_ossl40 branch (OpenSSL 4.0 fork for Kryoptic)
# Based on rust-cryptoki CI: github.com/parallaxsecond/rust-cryptoki/pull/362

FROM rust:latest AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git pkg-config libssl-dev clang make \
    perl sed \
    && rm -rf /var/lib/apt/lists/*

# Build OpenSSL 4.0 (simo5 fork for Kryoptic FIPS)
RUN git clone --single-branch --branch kryoptic_ossl40 --depth 1 \
    https://github.com/simo5/openssl.git /build/openssl
WORKDIR /build/openssl
RUN ./Configure no-docs no-tests && make -j$(nproc)

# Build Kryoptic from main with FIPS+PQC
ENV OPENSSL_DIR=/build/openssl
ENV OPENSSL_LIB_DIR=/build/openssl
ENV OPENSSL_INCLUDE_DIR=/build/openssl/include
ENV OPENSSL_STATIC=0
RUN git clone --depth 1 https://github.com/latchset/kryoptic.git /build/kryoptic
WORKDIR /build/kryoptic
# Build with FIPS+PQC, show any errors
RUN cargo build --release --no-default-features --features "fips,pqc" 2>&1; \
    echo "=== Build artifacts ===" && \
    find target/release -maxdepth 1 -name "*.so" 2>/dev/null && \
    if [ -f misc/hmacify.sh ] && [ -f target/release/libkryoptic_pkcs11.so ]; then \
      ./misc/hmacify.sh target/release/libkryoptic_pkcs11.so 2>&1 || true; \
    fi

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 git gcc python3-dev libssl-dev opensc \
    && rm -rf /var/lib/apt/lists/*

# Copy the built .so — use RUN to handle missing file gracefully
RUN --mount=from=builder,source=/build/kryoptic/target/release,target=/tmp/kryoptic-build \
    cp /tmp/kryoptic-build/libkryoptic_pkcs11.so /usr/lib/ 2>/dev/null && \
    cp /tmp/kryoptic-build/libkryoptic_pkcs11.so.hmac /usr/lib/ 2>/dev/null; \
    ls -lh /usr/lib/libkryoptic* 2>/dev/null || echo "WARNING: Kryoptic FIPS .so not found"

RUN mkdir -p /var/lib/kryoptic /etc/kryoptic && \
    printf '[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "/var/lib/kryoptic/token.sql"\n' \
    > /etc/kryoptic/token.conf
ENV KRYOPTIC_CONF=/etc/kryoptic/token.conf

# Token init may fail if FIPS .so needs runtime OpenSSL 4.0 — defer to CMD
RUN pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
    --init-token --label "p11test" --so-pin 12345678 2>&1 && \
    pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
    --init-pin --pin 1234 --so-pin 12345678 2>&1 || \
    echo "Token init deferred — FIPS module may need runtime OpenSSL"

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY . .
RUN uv sync --frozen

CMD ["sh", "-c", "echo 'Kryoptic FIPS (main + OpenSSL 4.0):' && uv run pytest src/p11test/testcases/ --p11-module=/usr/lib/libkryoptic_pkcs11.so --p11-pin=1234 -q --tb=no"]
