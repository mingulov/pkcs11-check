# qryptotoken — experimental pure-Rust PQC PKCS#11 token
# https://github.com/QUBIP/qryptotoken
#
# Post-quantum cryptography (PQC) PKCS#11 provider from the QUBIP project.
# This is experimental software — the build may fail or the module may not
# function correctly.  Failures are handled gracefully: if the build or init
# fails the CMD exits with a clear message rather than a hard error.

FROM fedora:44

# Rust toolchain via rustup (Fedora rustc may be too old for this crate)
RUN dnf install -y \
    git gcc openssl-devel pkg-config curl \
    clang-devel sqlite-devel \
    python3.14 python3.14-devel \
    && dnf clean all

# Install latest stable Rust via rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH="/root/.cargo/bin:$PATH"

# Build qryptotoken — cargo build produces the .so as a cdylib.
#
# The upstream target is experimental and can fail to compile on current Rust
# or bindgen/clang combinations. Keep the Docker target runnable so the release
# matrix records a build-unavailable artifact instead of stopping at image
# build time.
ARG QRYPTOTOKEN_REF="v0.4.1"
RUN git clone --depth 1 --branch "$QRYPTOTOKEN_REF" \
        https://github.com/QUBIP/qryptotoken.git /build/qryptotoken && \
    cd /build/qryptotoken && \
    git rev-parse HEAD > /tmp/qryptotoken_revision && \
    if cargo build --release 2>&1; then \
      find /build/qryptotoken/target/release -name "*.so" | head -5; \
    else \
      rc=$?; \
      echo "qryptotoken build failed with exit code $rc" | tee /tmp/qryptotoken_build_failed; \
    fi

# Locate the produced shared library
RUN find /build/qryptotoken/target/release -maxdepth 1 -name "*.so" 2>/dev/null \
        | head -1 > /tmp/module_path && \
    if [ -s /tmp/module_path ]; then \
      echo "qryptotoken module: $(cat /tmp/module_path)"; \
    else \
      echo "qryptotoken module: unavailable"; \
    fi

# Install opensc for pkcs11-tool (token init)
RUN dnf install -y opensc && dnf clean all

# Create token DB — qryptotoken needs an empty SQLite file first
RUN mkdir -p /root/.local/share/qryptotoken && \
    touch /root/.local/share/qryptotoken/token.sql && \
    MODULE=$(cat /tmp/module_path) && \
    if [ -n "$MODULE" ] && [ -f "$MODULE" ]; then \
      pkcs11-tool --module "$MODULE" \
        --init-token --label "pkcs11-check" --so-pin 12345678 2>&1 && \
      pkcs11-tool --module "$MODULE" \
        --init-pin --pin 1234 --so-pin 12345678 2>&1; \
    fi

# Test tooling: fault-proxy, pkcs11-provider, p11-kit
COPY docker/fault-proxy.c /tmp/fault-proxy.c
COPY docker/install-test-tools.sh /tmp/install-test-tools.sh
RUN bash /tmp/install-test-tools.sh && rm -f /tmp/install-test-tools.sh

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
# Install deps first (cached unless pyproject.toml/uv.lock change)
COPY pyproject.toml uv.lock README.md ./
COPY src/pkcs11_check/__init__.py src/pkcs11_check/__init__.py
COPY third_party/ third_party/
RUN uv sync --frozen --python python3.14

# Copy test code (changes frequently, does not invalidate deps cache)
COPY . .
ENV PKCS11_CHECK_PIN=1234

# Best-effort: run tests if the build produced a .so; report gracefully if not.
CMD ["bash", "/app/docker/run-with-artifacts.sh", "bash", "/app/docker/qryptotoken/run-qryptotoken.sh"]
