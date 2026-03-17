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
RUN git clone --depth 1 https://github.com/latchset/kryoptic.git /build/kryoptic
WORKDIR /build/kryoptic
RUN cargo build --no-default-features --features "fips,pqc" 2>&1 | tail -5 && \
    if [ -f misc/hmacify.sh ]; then \
      ./misc/hmacify.sh target/debug/libkryoptic_pkcs11.so 2>&1 || true; \
    fi

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 git gcc python3-dev libssl-dev opensc \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/kryoptic/target/debug/libkryoptic_pkcs11.so /usr/lib/
# Copy FIPS integrity files if they exist
COPY --from=builder /build/kryoptic/target/debug/libkryoptic_pkcs11.so.hmac /usr/lib/ 2>/dev/null || true

RUN mkdir -p /var/lib/kryoptic /etc/kryoptic && \
    printf '[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "/var/lib/kryoptic/token.sql"\n' \
    > /etc/kryoptic/token.conf
ENV KRYOPTIC_CONF=/etc/kryoptic/token.conf

RUN pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
    --init-token --label "p11test" --so-pin 12345678 2>&1 && \
    pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
    --init-pin --pin 1234 --so-pin 12345678 2>&1

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY . .
RUN uv sync --frozen

CMD ["sh", "-c", "echo 'Kryoptic FIPS (main + OpenSSL 4.0):' && uv run pytest src/p11test/testcases/ --p11-module=/usr/lib/libkryoptic_pkcs11.so --p11-pin=1234 -q --tb=no"]
