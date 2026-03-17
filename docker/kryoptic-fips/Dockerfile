# Kryoptic FIPS — main branch with FIPS+PQC features
# Uses simo5/openssl kryoptic_ossl40 branch (OpenSSL 4.0 fork)
# Matches: github.com/parallaxsecond/rust-cryptoki/pull/362

FROM rust:latest AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git pkg-config libssl-dev clang make perl \
    && rm -rf /var/lib/apt/lists/*

# Build OpenSSL 4.0 (simo5 fork for Kryoptic FIPS)
RUN git clone --single-branch --branch kryoptic_ossl40 --depth 1 \
    https://github.com/simo5/openssl.git /build/openssl
WORKDIR /build/openssl
RUN ./Configure no-docs no-tests && make -j$(nproc)

# Build Kryoptic from main with FIPS+PQC
# Key: KRYOPTIC_OPENSSL_SOURCES is the env var Kryoptic's build.rs uses
ENV KRYOPTIC_OPENSSL_SOURCES=/build/openssl
RUN git clone --depth 1 https://github.com/latchset/kryoptic.git /build/kryoptic
WORKDIR /build/kryoptic
RUN cargo build -vv --no-default-features --features "fips,pqc" 2>&1 | tail -10 && \
    ls -lh target/debug/libkryoptic_pkcs11.so && \
    if [ -f misc/hmacify.sh ]; then \
      ./misc/hmacify.sh target/debug/libkryoptic_pkcs11.so 2>&1; \
    fi

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git gcc python3-dev libssl-dev opensc \
    && rm -rf /var/lib/apt/lists/*

# Copy Kryoptic FIPS module + OpenSSL 4.0 runtime libs
COPY --from=builder /build/kryoptic/target/debug/libkryoptic_pkcs11.so /usr/lib/
COPY --from=builder /build/openssl/libcrypto.so.4 /usr/lib/
COPY --from=builder /build/openssl/libssl.so.4 /usr/lib/
RUN ldconfig

# Copy HMAC file from builder (COPY is byte-exact, so HMAC should match)
COPY --from=builder /build/kryoptic/target/debug/libkryoptic_pkcs11.so.hmac /usr/lib/

RUN mkdir -p /var/lib/kryoptic /etc/kryoptic && \
    printf '[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "/var/lib/kryoptic/token.sql"\n' \
    > /etc/kryoptic/token.conf
ENV KRYOPTIC_CONF=/etc/kryoptic/token.conf

# Init token — may need LD_LIBRARY_PATH for OpenSSL 4.0
RUN LD_LIBRARY_PATH=/usr/lib pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
    --init-token --label "p11test" --so-pin 12345678 2>&1 && \
    LD_LIBRARY_PATH=/usr/lib pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
    --init-pin --pin 1234 --so-pin 12345678 2>&1 || \
    echo "Token init needs runtime fix"

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY . .
RUN uv sync --frozen

CMD ["sh", "-c", "echo 'Kryoptic FIPS (main + OpenSSL 4.0):' && LD_LIBRARY_PATH=/usr/lib uv run pytest src/p11test/testcases/ --p11-module=/usr/lib/libkryoptic_pkcs11.so --p11-pin=1234 -q --tb=no"]
