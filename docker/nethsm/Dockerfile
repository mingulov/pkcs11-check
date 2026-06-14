# NetHSM — co-located keyfender server (from nitrokey/nethsm:testing) + nethsm-pkcs11 module.
# Server and module talk over 127.0.0.1, so the target runs under network_mode: none.
# nethsm-pkcs11 keygen auto-escalates to the NetHSM administrator (creds in p11nethsm.conf).

# --- Builder: compile the PKCS#11 module with MUSL so it loads on the Alpine final stage.
# The runtime image (nitrokey/nethsm:testing) is Alpine/musl and has no glibc loader
# (ld-linux-x86-64.so.2), so a glibc-built .so fails to load. rust:alpine builds musl by
# default; statically link OpenSSL so the .so has no external libssl dependency at run time. ---
FROM rust:alpine AS builder
ARG NETHSM_PKCS11_REF="v2.2.0"
RUN apk add --no-cache git musl-dev openssl-dev openssl-libs-static pkgconf perl make
ENV OPENSSL_STATIC=1
# musl defaults to static linking, which cannot produce a cdylib (.so). Disable crt-static so
# the module builds as a dynamic musl shared library that loads on the Alpine runtime.
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN git clone --depth 1 --branch "$NETHSM_PKCS11_REF" \
    https://github.com/Nitrokey/nethsm-pkcs11.git /build/m
WORKDIR /build/m
RUN cargo build --release && test -f target/release/libnethsm_pkcs11.so

# --- Final: the NetHSM testing image (Alpine; ships keyfender.unix + etcd + /start.sh) ---
FROM nitrokey/nethsm:testing

# Toolchain for the suite + test tooling (Alpine/musl). Alpine 3.23 ships Python 3.12.13,
# which satisfies the suite's >=3.12 floor — so uv uses the system python directly (no managed
# interpreter needed). bash: install-test-tools.sh and run-pkcs11-check.sh are bash scripts.
# Build deps cover any sdist-only Python wheels and the fault-proxy compile.
RUN apk add --no-cache bash curl ca-certificates gcc musl-dev libgcc \
    python3 python3-dev libffi-dev openssl-dev make opensc

# uv (the installer auto-detects the musl target).
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

# Shared test tooling (now apk-aware): p11-kit, pkcs11-provider (best-effort), fault-proxy.
COPY docker/fault-proxy.c /tmp/fault-proxy.c
COPY docker/install-test-tools.sh /tmp/install-test-tools.sh
RUN bash /tmp/install-test-tools.sh && rm -f /tmp/install-test-tools.sh

COPY --from=builder /build/m/target/release/libnethsm_pkcs11.so /usr/lib/
COPY docker/nethsm/p11nethsm.conf /etc/nitrokey/p11nethsm.conf
COPY docker/nethsm/run-nethsm.sh /usr/local/bin/run-nethsm.sh
RUN chmod +x /usr/local/bin/run-nethsm.sh

ENV P11NETHSM_CONFIG_FILE=/etc/nitrokey/p11nethsm.conf
ENV PKCS11_CHECK_MODULE=/usr/lib/libnethsm_pkcs11.so
ENV PKCS11_CHECK_PIN=opPassphrase1

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src/pkcs11_check/__init__.py src/pkcs11_check/__init__.py
COPY third_party/ third_party/
# Build the venv against Alpine's system Python 3.12 so run-pkcs11-check.sh's
# `command -v python3` matches the venv interpreter.
RUN uv sync --frozen --python /usr/bin/python3

COPY . .

# The base image's ENTRYPOINT is /start.sh; reset it so our CMD is the full command. We drive
# /start.sh ourselves from run-nethsm.sh (start server -> provision -> create operator -> run).
ENTRYPOINT []
CMD ["bash", "/app/docker/run-with-artifacts.sh", "bash", "/usr/local/bin/run-nethsm.sh"]
