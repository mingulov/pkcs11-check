# craton-hsm-core — pure-Rust PKCS#11 v3.0 software HSM (built from main; no release tags).
# In-process module, no daemon, no network at run time. Mirrors kryoptic/Dockerfile.main minus
# the OpenSSL stage (RustCrypto default backend).
#
# PATCHED: craton's in-process module keeps token auth in memory per process, and pkcs11-check
# runs each test file in its own subprocess — so a pre-provisioned token would be invisible at
# run time. The pkcs11-check patch (docker/craton-hsm/patches/) adds initial_so_pin /
# initial_user_pin config so the token auto-provisions at C_Initialize in every process.
# See docs/findings/craton-hsm-feasibility-2026-06-14.md.

FROM rust:latest AS builder

ARG CRATON_REF="main"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "$CRATON_REF" \
    https://github.com/craton-co/craton-hsm-core.git /build/craton
WORKDIR /build/craton

# Apply pkcs11-check patches (auto-init token from config).
COPY docker/craton-hsm/patches/ /tmp/patches/
RUN for p in /tmp/patches/*.patch; do \
        echo "Applying patch: $p"; \
        git apply --verbose "$p"; \
    done

# Build ONLY the craton-hsm cdylib (package is hyphenated; the lib is craton_hsm ->
# libcraton_hsm.so). NOT --workspace: that also builds pkcs11-spy and pulls protoc/cmake.
RUN cargo build --release -p craton-hsm

FROM python:3.14-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc python3-dev opensc \
    && rm -rf /var/lib/apt/lists/*

# Test tooling: fault-proxy, pkcs11-provider, p11-kit
COPY docker/fault-proxy.c /tmp/fault-proxy.c
COPY docker/install-test-tools.sh /tmp/install-test-tools.sh
RUN bash /tmp/install-test-tools.sh && rm -f /tmp/install-test-tools.sh

COPY --from=builder /build/craton/target/release/libcraton_hsm.so /usr/lib/

# Our locally-built module is unsigned (embedded integrity public key is the all-zeros
# placeholder), so craton refuses to C_Initialize unless this documented dev/test bypass is set.
ENV CRATON_HSM_INTEGRITY_BYPASS=unsafe-dev-only
ENV PKCS11_CHECK_MODULE=/usr/lib/libcraton_hsm.so
ENV PKCS11_CHECK_PIN=UserPin1

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src/pkcs11_check/__init__.py src/pkcs11_check/__init__.py
COPY third_party/ third_party/
RUN uv sync --frozen

COPY . .

# craton config (relative path via the default craton_hsm.toml lookup in CWD /app — craton
# rejects absolute config/storage paths). The auto-init patch provisions the token from these
# PINs at C_Initialize, so every test subprocess sees a ready token. Verify login works in a
# FRESH process at build time — this proves the cross-process provisioning fix.
RUN printf '[security]\ninitial_so_pin = "SoPin1234"\ninitial_user_pin = "UserPin1"\n' \
    > /app/craton_hsm.toml && \
    pkcs11-tool --module /usr/lib/libcraton_hsm.so --login --pin UserPin1 -O && \
    echo "craton auto-init verified: login succeeded in a fresh process"

CMD ["bash", "/app/docker/run-with-artifacts.sh", "bash", "/app/docker/run-pkcs11-check.sh"]
