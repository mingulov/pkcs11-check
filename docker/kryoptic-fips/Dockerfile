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
# Per rust-cryptoki PR #362: fips,pqc (no dummy-integrity — it's removed)
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

# Copy OpenSSL 4.0 binary for hmacify + fipsinstall
COPY --from=builder /build/openssl/apps/openssl /usr/local/bin/openssl40
COPY --from=builder /build/openssl/providers/fips.so /usr/lib/ossl-modules/fips.so
RUN mkdir -p /usr/lib/ossl-modules

# Run fipsinstall to create the FIPS config
RUN LD_LIBRARY_PATH=/usr/lib /usr/local/bin/openssl40 fipsinstall \
    -out /usr/lib/fipsmodule.cnf -module /usr/lib/ossl-modules/fips.so 2>&1 || true

# HMAC the Kryoptic .so
COPY --from=builder /build/kryoptic/misc/hmacify.sh /tmp/hmacify.sh
RUN chmod +x /tmp/hmacify.sh && \
    PATH=/usr/local/bin:$PATH LD_LIBRARY_PATH=/usr/lib \
    /tmp/hmacify.sh /usr/lib/libkryoptic_pkcs11.so 2>&1 && \
    rm /tmp/hmacify.sh

RUN mkdir -p /var/lib/kryoptic /etc/kryoptic && \
    printf '[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "/var/lib/kryoptic/token.sql"\n' \
    > /etc/kryoptic/token.conf
ENV KRYOPTIC_CONF=/etc/kryoptic/token.conf

# Init token — may need LD_LIBRARY_PATH for OpenSSL 4.0
RUN LD_LIBRARY_PATH=/usr/lib pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
    --init-token --label "pkcs11-check" --so-pin 12345678 2>&1 && \
    LD_LIBRARY_PATH=/usr/lib pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
    --init-pin --pin 1234 --so-pin 12345678 2>&1 || \
    echo "Token init needs runtime fix"

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY . .
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_PYTHON_PKCS11=0.0
RUN uv sync --frozen

# Create OpenSSL config that activates the FIPS provider
RUN printf '[openssl_init]\nproviders = provider_sect\n\n[provider_sect]\nfips = fips_sect\nbase = base_sect\n\n[base_sect]\nactivate = 1\n\n[fips_sect]\nactivate = 1\nmodule-mac-mismatch = 1\n' \
    > /etc/openssl-fips.cnf

ENV OPENSSL_CONF=/etc/openssl-fips.cnf
ENV OPENSSL_MODULES=/usr/lib/ossl-modules
ENV PKCS11_CHECK_MODULE=/usr/lib/libkryoptic_pkcs11.so
ENV PKCS11_CHECK_PIN=1234

CMD ["bash", "/app/docker/run-with-artifacts.sh", "sh", "-c", "echo 'Kryoptic FIPS (main + OpenSSL 4.0):' && env LD_LIBRARY_PATH=/usr/lib bash /app/docker/run-pkcs11-check.sh"]
