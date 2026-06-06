# BouncyHSM — .NET PKCS#11 simulator with BouncyCastle crypto

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends git build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY patches/bouncyhsm/0001-fix-getattributevalue-rvmethod.patch /tmp/bouncyhsm-patches/
RUN git clone --depth 1 --branch v2.1.1 https://github.com/harrison314/BouncyHsm.git /build/bouncyhsm
WORKDIR /build/bouncyhsm
RUN git apply --ignore-space-change --ignore-whitespace \
        /tmp/bouncyhsm-patches/0001-fix-getattributevalue-rvmethod.patch && \
    dotnet publish src/Src/BouncyHsm/BouncyHsm.csproj -c Release -o /app/server \
        >/tmp/dotnet-publish.log && \
    tail -3 /tmp/dotnet-publish.log && \
    make -C build_linux CC=gcc && \
    cp build_linux/BouncyHsm.Pkcs11Lib-x64.so /app/libbouncyhsm_pkcs11.so

FROM python:3.14-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git gcc python3-dev libssl-dev curl libicu-dev \
    && rm -rf /var/lib/apt/lists/*

# Test tooling: fault-proxy, pkcs11-provider, p11-kit
COPY docker/fault-proxy.c /tmp/fault-proxy.c
COPY docker/install-test-tools.sh /tmp/install-test-tools.sh
RUN bash /tmp/install-test-tools.sh && rm -f /tmp/install-test-tools.sh

COPY --from=mcr.microsoft.com/dotnet/aspnet:10.0 /usr/share/dotnet /usr/share/dotnet
ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH=$PATH:/usr/share/dotnet

COPY --from=builder /app/server /opt/bouncyhsm
RUN --mount=from=builder,source=/app,target=/tmp/builder \
    cp /tmp/builder/libbouncyhsm_pkcs11.so /usr/lib/ 2>/dev/null || \
    echo "No native PKCS#11 lib found"

# LiteDB storage config
RUN mkdir -p /opt/bouncyhsm/data && \
    printf '{\n  "BouncyHsm": {\n    "PersistenceStorageType": "LiteDbFile",\n    "LiteDbFilePersistence": {\n      "ConnectionString": "Filename=/opt/bouncyhsm/data/BouncyHsm.db;Connection=shared"\n    },\n    "ProtectedAuthPathStorage": "InMemory"\n  }\n}\n' \
    > /opt/bouncyhsm/appsettings.Production.json

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
# Install deps first (cached unless pyproject.toml/uv.lock change)
COPY pyproject.toml uv.lock README.md ./
COPY src/pkcs11_check/__init__.py src/pkcs11_check/__init__.py
COPY third_party/ third_party/
RUN uv sync --frozen

# Copy test code (changes frequently, does not invalidate deps cache)
COPY . .
ENV PKCS11_CHECK_PIN=1234

# BouncyHSM needs slots created via its management interface.
# The PKCS#11 lib connects to the server via TCP socket.
CMD ["bash", "/app/docker/run-with-artifacts.sh", "bash", "/app/docker/bouncyhsm/run-bouncyhsm.sh"]
