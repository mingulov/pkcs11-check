# craton-hsm-core — pure-Rust PKCS#11 v3.0 software HSM (built from main; no release tags).
# In-process module, no daemon, no network at run time. Mirrors kryoptic/Dockerfile.main
# minus the OpenSSL-from-source stage (craton's default backend is RustCrypto, pure Rust).

FROM rust:latest AS builder

ARG CRATON_REF="main"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "$CRATON_REF" \
    https://github.com/craton-co/craton-hsm-core.git /build/craton
WORKDIR /build/craton
# Build ONLY the root cdylib crate. NOT --workspace: the optional gRPC daemon needs protoc
# and the awslc/fips features need cmake; default features = rustcrypto-backend (what we want).
# If the package name differs, `cargo metadata` / `ls target/release/*.so` reveals the real
# crate; adjust -p and the COPY below accordingly.
RUN cargo build --release -p craton_hsm

FROM python:3.14-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc python3-dev opensc \
    && rm -rf /var/lib/apt/lists/*

# Test tooling: fault-proxy, pkcs11-provider, p11-kit
COPY docker/fault-proxy.c /tmp/fault-proxy.c
COPY docker/install-test-tools.sh /tmp/install-test-tools.sh
RUN bash /tmp/install-test-tools.sh && rm -f /tmp/install-test-tools.sh

COPY --from=builder /build/craton/target/release/libcraton_hsm.so /usr/lib/

# Writable redb-backed token store + a minimal explicit config (lib also has secure
# defaults; we pin the storage path and a single slot).
RUN mkdir -p /var/lib/craton /etc/craton && \
    printf '[token]\nstorage_path = "/var/lib/craton/store"\npersist_objects = true\nslot_count = 1\n' \
    > /etc/craton/craton_hsm.toml
ENV CRATON_HSM_CONFIG=/etc/craton/craton_hsm.toml

# Token init. If --init-token reports no slot, add `--slot 0` (matches slot_count=1).
RUN pkcs11-tool --module /usr/lib/libcraton_hsm.so \
    --init-token --label "pkcs11-check" --so-pin 12345678 && \
    pkcs11-tool --module /usr/lib/libcraton_hsm.so \
    --init-pin --pin 1234 --so-pin 12345678

ENV PKCS11_CHECK_MODULE=/usr/lib/libcraton_hsm.so
ENV PKCS11_CHECK_PIN=1234

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src/pkcs11_check/__init__.py src/pkcs11_check/__init__.py
COPY third_party/ third_party/
RUN uv sync --frozen

COPY . .

CMD ["bash", "/app/docker/run-with-artifacts.sh", "bash", "/app/docker/run-pkcs11-check.sh"]
