# Kryoptic FIPS — main branch with FIPS+PQC features
# Uses simo5/openssl kryoptic_ossl40 branch (OpenSSL 4.0 fork)
# Ref: github.com/parallaxsecond/rust-cryptoki/pull/362
#
# STATUS: BROKEN — Kryoptic FIPS self-test (provider.rs:713) panics during
# C_Initialize in Docker. The statically-linked OpenSSL 4.0 FIPS provider
# fails module integrity verification. The reference CI (rust-cryptoki #362)
# runs on Fedora, not Debian-based containers. Needs investigation into
# OpenSSL 4.0-alpha FIPS self-test requirements in Docker environments.
# Tracked in: docs/module-issues.md

FROM rust:latest AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git pkg-config libssl-dev clang make perl openssl \
    && rm -rf /var/lib/apt/lists/*

# Build OpenSSL 4.0 (simo5 fork for Kryoptic FIPS)
RUN git clone --single-branch --branch kryoptic_ossl40 --depth 1 \
    https://github.com/simo5/openssl.git /build/openssl
WORKDIR /build/openssl
RUN ./Configure no-docs no-tests && make -j$(nproc)

# Build Kryoptic from main with FIPS+PQC
ENV KRYOPTIC_OPENSSL_SOURCES=/build/openssl
RUN git clone --depth 1 https://github.com/latchset/kryoptic.git /build/kryoptic
WORKDIR /build/kryoptic
RUN cargo build -vv --no-default-features --features "fips,pqc" 2>&1 | tail -20
RUN ./misc/hmacify.sh target/debug/libkryoptic_pkcs11.so

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git gcc python3-dev libssl-dev opensc \
    && rm -rf /var/lib/apt/lists/*

# Keep module + OpenSSL at build paths for FIPS integrity verification
COPY --from=builder /build/kryoptic/target/debug/libkryoptic_pkcs11.so /build/kryoptic/target/debug/
COPY --from=builder /build/kryoptic/target/debug/libkryoptic_pkcs11.so.hmac /build/kryoptic/target/debug/
COPY --from=builder /build/openssl/libcrypto.so.4 /build/openssl/libcrypto.so.4
COPY --from=builder /build/openssl/libssl.so.4 /build/openssl/libssl.so.4
RUN ln -s /build/kryoptic/target/debug/libkryoptic_pkcs11.so /usr/lib/libkryoptic_pkcs11.so && \
    ln -s /build/openssl/libcrypto.so.4 /usr/lib/ && \
    ln -s /build/openssl/libssl.so.4 /usr/lib/ && \
    ldconfig

RUN mkdir -p /var/lib/kryoptic /etc/kryoptic && \
    printf '[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "/var/lib/kryoptic/token.sql"\n' \
    > /etc/kryoptic/token.conf
ENV KRYOPTIC_CONF=/etc/kryoptic/token.conf

# Token init — will fail until FIPS self-test issue is resolved
RUN LD_LIBRARY_PATH=/usr/lib pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
    --init-token --label "pkcs11-check" --so-pin 12345678 2>&1 && \
    LD_LIBRARY_PATH=/usr/lib pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
    --init-pin --pin 1234 --so-pin 12345678 2>&1 || \
    echo "WARNING: Token init failed (FIPS self-test issue)"

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY python-pkcs11/ python-pkcs11/
COPY src/pkcs11_check/__init__.py src/pkcs11_check/__init__.py
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_PYTHON_PKCS11=0.0
RUN uv sync --frozen

COPY . .

ENV LD_LIBRARY_PATH=/usr/lib
ENV PKCS11_CHECK_MODULE=/usr/lib/libkryoptic_pkcs11.so
ENV PKCS11_CHECK_PIN=1234

CMD ["bash", "/app/docker/run-with-artifacts.sh", "bash", "/app/docker/run-pkcs11-check.sh"]
