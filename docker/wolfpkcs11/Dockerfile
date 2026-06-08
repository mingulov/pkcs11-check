# wolfPKCS11 — wolfSSL-backed PKCS#11 provider
#
# Build args:
#   WOLFSSL_REF          wolfSSL git tag or branch
#   WOLFPKCS11_REPO      wolfPKCS11 git repository URL
#   WOLFPKCS11_REF       wolfPKCS11 git tag or branch
#   WOLFPKCS11_ENABLE_PQC=1 enables wolfPKCS11 PKCS#11 v3.2 + ML-DSA/ML-KEM

FROM debian:trixie AS builder

ARG WOLFSSL_REF="v5.9.1-stable"
ARG WOLFPKCS11_REPO="https://github.com/wolfSSL/wolfPKCS11.git"
ARG WOLFPKCS11_REF="v2.0.0-stable"
ARG WOLFPKCS11_ENABLE_PQC="0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake build-essential ca-certificates git libtool pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "$WOLFSSL_REF" \
    https://github.com/wolfSSL/wolfssl.git /build/wolfssl
WORKDIR /build/wolfssl
RUN ./autogen.sh && \
    wolfssl_pqc_args="" && \
    if [ "$WOLFPKCS11_ENABLE_PQC" = "1" ]; then \
        wolfssl_pqc_args="--enable-mldsa --enable-mlkem"; \
    fi && \
    ./configure \
        --prefix=/usr/local \
        --enable-shared \
        --disable-static \
        --enable-aescfb \
        --enable-aesccm \
        --enable-aesctr \
        --enable-aescts \
        --enable-aesecb \
        --enable-aeskeywrap \
        --enable-cmac \
        --enable-cryptocb \
        --enable-hkdf \
        --enable-keygen \
        --enable-pwdbased \
        --enable-rsapss \
        --enable-scrypt \
        --enable-sha3 \
        $wolfssl_pqc_args \
        C_EXTRA_FLAGS="-DWOLFSSL_PUBLIC_MP -DWC_RSA_DIRECT -DHAVE_AES_ECB -DHAVE_AES_KEYWRAP" && \
    make -j"$(nproc)" && \
    make install

RUN git clone --depth 1 --branch "$WOLFPKCS11_REF" \
    "$WOLFPKCS11_REPO" /build/wolfpkcs11
WORKDIR /build/wolfpkcs11
RUN ./autogen.sh && \
    wolfpkcs11_pqc_args="" && \
    if [ "$WOLFPKCS11_ENABLE_PQC" = "1" ]; then \
        wolfpkcs11_pqc_args="--enable-pkcs11v32 --enable-mldsa --enable-mlkem"; \
    fi && \
    PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
    LD_LIBRARY_PATH=/usr/local/lib \
    ./configure \
        --prefix=/usr/local \
        --enable-aeskeywrap \
        --enable-aesctr \
        --enable-aesccm \
        --enable-aesecb \
        --enable-aescts \
        --enable-aescmac \
        --enable-pbkdf2 \
        $wolfpkcs11_pqc_args && \
    make -j"$(nproc)" && \
    make install && \
    cp examples/init_token /usr/local/bin/wolfpkcs11-init-token

FROM python:3.14-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates gcc git libc6-dev libtool opensc python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Test tooling: fault-proxy, pkcs11-provider, p11-kit
COPY docker/fault-proxy.c /tmp/fault-proxy.c
COPY docker/install-test-tools.sh /tmp/install-test-tools.sh
RUN bash /tmp/install-test-tools.sh && rm -f /tmp/install-test-tools.sh

COPY --from=builder /usr/local/ /usr/local/
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/wolfpkcs11.conf && ldconfig

ENV WOLFPKCS11_TOKEN_PATH=/var/lib/wolfpkcs11
RUN mkdir -p "$WOLFPKCS11_TOKEN_PATH" && \
    wolfpkcs11-init-token \
        -lib /usr/local/lib/libwolfpkcs11.so \
        -token pkcs11-check \
        -soPin 12345678 \
        -userPin 1234

ENV PKCS11_CHECK_MODULE=/usr/local/lib/libwolfpkcs11.so
ENV PKCS11_CHECK_PIN=1234
ENV PKCS11_CHECK_SLOT=0

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
# Install deps first (cached unless pyproject.toml/uv.lock change)
COPY pyproject.toml uv.lock README.md ./
COPY src/pkcs11_check/__init__.py src/pkcs11_check/__init__.py
COPY third_party/ third_party/
RUN uv sync --frozen

# Copy test code (changes frequently, does not invalidate deps cache)
COPY . .

CMD ["bash", "/app/docker/run-with-artifacts.sh", "bash", "/app/docker/run-pkcs11-check.sh"]
