# corePKCS11 - FreeRTOS MbedTLS software PKCS#11 implementation
#
# Build args:
#   COREPKCS11_REF      corePKCS11 git tag or branch

FROM debian:trixie AS builder

ARG COREPKCS11_REF="v3.6.4"

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates cmake git ninja-build pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "$COREPKCS11_REF" \
    https://github.com/FreeRTOS/corePKCS11.git /build/corePKCS11

COPY docker/corepkcs11/corepkcs11_malloc.c /build/corepkcs11_malloc.c
COPY docker/corepkcs11/corepkcs11_pal_generic.c /build/corepkcs11_pal_generic.c
COPY docker/corepkcs11/core_pkcs11_config.h /build/core_pkcs11_config.h

WORKDIR /build/corePKCS11
# The stock posix PAL only stores the eight fixed configured labels (anything else
# fails C_CreateObject with CKR_DEVICE_MEMORY); swap in the generic in-memory PAL
# so corePKCS11 is exercisable as a general provider. See corepkcs11_pal_generic.c.
RUN cp /build/core_pkcs11_config.h test/include/core_pkcs11_config.h && \
    perl -0pi -e 's#set\( PKCS_PAL_POSIX_SOURCES.*?\)#set( PKCS_PAL_POSIX_SOURCES\n     "/build/corepkcs11_pal_generic.c"\n     )#s' pkcsFilePaths.cmake && \
    grep -q corepkcs11_pal_generic pkcsFilePaths.cmake && \
    perl -0pi -e 's#target_sources\( core_pkcs PUBLIC \$\{PKCS_SOURCES\}\n#target_sources( core_pkcs PUBLIC \${PKCS_SOURCES}\n                                      /build/corepkcs11_malloc.c\n#' CMakeLists.txt && \
    cmake -S . -B /build/corePKCS11-build -GNinja \
        -DSTANDALONE_TEST_BUILD_UNIX=ON \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /build/corePKCS11-build --target core_pkcs -j"$(nproc)"

COPY docker/corepkcs11/corepkcs11_adapter.c /build/corepkcs11_adapter.c

RUN mkdir -p /usr/local/lib && \
    find /build/corePKCS11-build -name 'libmbed*.so*' -exec cp -a {} /usr/local/lib/ \; && \
    cp /build/corePKCS11-build/libcore_pkcs.so /usr/local/lib/libcore_pkcs.so && \
    cc -fPIC -shared -O2 -Wall -Wextra \
        -I/build/corePKCS11-build/_deps/pkcs11-src/published/2-40-errata-1 \
        -o /usr/local/lib/libcorepkcs11_adapter.so \
        /build/corepkcs11_adapter.c \
        -ldl && \
    ldd /usr/local/lib/libcore_pkcs.so && \
    ldd /usr/local/lib/libcorepkcs11_adapter.so

FROM python:3.14-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates gcc git libc6-dev libtool opensc python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Test tooling: fault-proxy, pkcs11-provider, p11-kit
COPY docker/fault-proxy.c /tmp/fault-proxy.c
COPY docker/install-test-tools.sh /tmp/install-test-tools.sh
RUN bash /tmp/install-test-tools.sh && rm -f /tmp/install-test-tools.sh

COPY --from=builder /usr/local/lib/libcore_pkcs.so /usr/local/lib/libcore_pkcs.so
COPY --from=builder /usr/local/lib/libcorepkcs11_adapter.so /usr/local/lib/libcorepkcs11_adapter.so
COPY --from=builder /usr/local/lib/libmbed*.so* /usr/local/lib/
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/corepkcs11.conf && ldconfig

ENV COREPKCS11_REAL_MODULE=/usr/local/lib/libcore_pkcs.so
ENV PKCS11_CHECK_MODULE=/usr/local/lib/libcorepkcs11_adapter.so
ENV PKCS11_CHECK_PIN=0000
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
