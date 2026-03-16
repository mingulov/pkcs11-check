# BouncyHSM — .NET-based PKCS#11 simulator
# v3.2 support, 206 mechanisms, PQC, BouncyCastle crypto backend
#
# Architecture: PKCS#11 native lib → gRPC → BouncyHsm server (.NET)

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends git unzip \
    && rm -rf /var/lib/apt/lists/*

# Build BouncyHSM server
RUN git clone --depth 1 https://github.com/harrison314/BouncyHsm.git /build/bouncyhsm
WORKDIR /build/bouncyhsm
RUN dotnet publish src/Src/BouncyHsm/BouncyHsm.csproj -c Release -o /app/server 2>&1 | tail -5

# Extract native PKCS#11 lib from NuGet package
RUN dotnet new console -o /tmp/nuget-extract && \
    cd /tmp/nuget-extract && \
    dotnet add package BouncyHsm.Client 2>&1 | tail -3 && \
    find ~/.nuget -name "BouncyHsm.Pkcs11Lib.so" -o -name "libBouncyHsm*.so" 2>/dev/null | head -5 && \
    find ~/.nuget -path "*/runtimes/linux*/native/*.so" 2>/dev/null | head -10

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git gcc python3-dev libssl-dev curl libicu-dev \
    && rm -rf /var/lib/apt/lists/*

# Install .NET ASP.NET runtime for server
COPY --from=mcr.microsoft.com/dotnet/aspnet:10.0 /usr/share/dotnet /usr/share/dotnet
ENV DOTNET_ROOT=/usr/share/dotnet
ENV PATH=$PATH:/usr/share/dotnet

# Copy server
COPY --from=builder /app/server /opt/bouncyhsm

# Copy native PKCS#11 lib — try multiple possible locations
COPY --from=builder /root/.nuget/ /tmp/nuget/
RUN find /tmp/nuget -name "*.so" -path "*/linux*" 2>/dev/null | head -5 && \
    PKCS11_LIB=$(find /tmp/nuget -name "*.so" -path "*/linux-x64/*" 2>/dev/null | head -1) && \
    if [ -n "$PKCS11_LIB" ]; then \
        cp "$PKCS11_LIB" /usr/lib/libbouncyhsm_pkcs11.so && \
        echo "Found PKCS#11 lib: $PKCS11_LIB"; \
    else \
        echo "WARNING: No PKCS#11 native lib found in NuGet"; \
    fi && \
    rm -rf /tmp/nuget

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY . .
RUN uv sync --frozen

CMD ["sh", "-c", "\
  echo 'BouncyHSM server starting...' && \
  dotnet /opt/bouncyhsm/BouncyHsm.dll --urls http://localhost:5000 &>/dev/null & \
  sleep 3 && \
  if [ -f /usr/lib/libbouncyhsm_pkcs11.so ]; then \
    echo 'PKCS#11 lib found' && \
    uv run pytest src/p11test/testcases/ \
      --p11-module=/usr/lib/libbouncyhsm_pkcs11.so -q --tb=no; \
  else \
    echo 'BouncyHSM PKCS#11 native lib not available'; \
  fi"]
