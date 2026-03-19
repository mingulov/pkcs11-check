# pkcs11-mock — minimal PKCS#11 mock library
# https://github.com/Pkcs11Interop/pkcs11-mock
#
# A single-file C stub that implements the PKCS#11 v3.1 interface with
# stub/minimal responses. Useful for testing that pkcs11-check handles modules
# that return CKR_FUNCTION_NOT_SUPPORTED or minimal data gracefully.
#
# No token initialization needed — the mock accepts any call and returns
# canned values.

FROM fedora:43

RUN dnf install -y \
    git gcc \
    python3.12 python3.12-devel \
    openssl-devel \
    && dnf clean all

# Build pkcs11-mock from source.
# The project is a single C file compiled to a shared library.
RUN git clone --depth 1 https://github.com/Pkcs11Interop/pkcs11-mock.git \
        /build/pkcs11-mock && \
    gcc -shared -fPIC -o /usr/lib64/libpkcs11-mock.so \
        /build/pkcs11-mock/src/pkcs11-mock.c \
        -I /build/pkcs11-mock/src \
        -Wl,-soname,libpkcs11-mock.so \
        2>&1 && \
    echo "Build OK: $(ls -lh /usr/lib64/libpkcs11-mock.so)"

ENV P11TEST_MODULE=/usr/lib64/libpkcs11-mock.so

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY . .
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_PYTHON_PKCS11=0.0
RUN uv python pin 3.12 && uv sync --frozen

# No PIN needed — mock ignores it.
# Tests are expected to skip or fail gracefully where the mock returns
# CKR_FUNCTION_NOT_SUPPORTED; that is intentional and valuable signal.
CMD ["sh", "-c", "\
  echo 'pkcs11-mock library:' && \
  ls -lh /usr/lib64/libpkcs11-mock.so && \
  uv run pytest src/pkcs11_check/testcases/ \
    --p11-module=/usr/lib64/libpkcs11-mock.so \
    -q --tb=short 2>&1 || true"]
