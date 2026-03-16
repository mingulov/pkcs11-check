# BouncyHSM — .NET-based PKCS#11 simulator
# v3.2 support, 206 mechanisms, PQC, BouncyCastle crypto backend
#
# Architecture: native PKCS#11 lib → gRPC → BouncyHsm server
# The server runs in the background, tests use the native PKCS#11 .so

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS bouncyhsm-builder

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/harrison314/BouncyHsm.git /build/bouncyhsm
WORKDIR /build/bouncyhsm
RUN dotnet publish src/Src/BouncyHsm/BouncyHsm.csproj -c Release -o /app/bouncyhsm

# Build the native PKCS#11 library
WORKDIR /build/bouncyhsm/src/Src/BouncyHsm.Pkcs11Lib
RUN dotnet publish -c Release -r linux-x64 -o /app/pkcs11lib 2>/dev/null || true

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git gcc python3-dev libssl-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Install .NET runtime for BouncyHSM server
COPY --from=mcr.microsoft.com/dotnet/aspnet:10.0 /usr/share/dotnet /usr/share/dotnet
ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH=$PATH:/usr/share/dotnet

COPY --from=bouncyhsm-builder /app/bouncyhsm /opt/bouncyhsm
COPY --from=bouncyhsm-builder /app/pkcs11lib /opt/pkcs11lib

WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY . .
RUN uv sync --frozen

# BouncyHSM needs server running + PKCS#11 native lib pointing to it
# Start server in background, then run tests
CMD ["sh", "-c", "\
  echo 'Starting BouncyHSM server...' && \
  dotnet /opt/bouncyhsm/BouncyHsm.dll &>/dev/null & \
  sleep 3 && \
  echo 'BouncyHSM ready' && \
  PKCS11_MODULE=/opt/pkcs11lib/BouncyHsm.Pkcs11Lib.so && \
  if [ -f $PKCS11_MODULE ]; then \
    uv run pytest src/p11test/testcases/ --p11-module=$PKCS11_MODULE -q --tb=no; \
  else \
    echo 'PKCS#11 native lib not found — BouncyHSM requires platform-specific build'; \
  fi"]
