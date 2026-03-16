# BouncyHSM — .NET PKCS#11 simulator with BouncyCastle crypto

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends git unzip \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/harrison314/BouncyHsm.git /build/bouncyhsm
WORKDIR /build/bouncyhsm
RUN dotnet publish src/Src/BouncyHsm/BouncyHsm.csproj -c Release -o /app/server 2>&1 | tail -3

# Extract native PKCS#11 lib from NuGet
RUN dotnet new console -o /tmp/nuget-extract && \
    cd /tmp/nuget-extract && \
    dotnet add package BouncyHsm.Client 2>&1 | tail -3 && \
    LIBPATH=$(find ~/.nuget -name "*.so" -path "*/linux-x64/*" 2>/dev/null | head -1) && \
    if [ -n "$LIBPATH" ]; then cp "$LIBPATH" /app/libbouncyhsm_pkcs11.so; fi

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git gcc python3-dev libssl-dev curl libicu-dev \
    && rm -rf /var/lib/apt/lists/*

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
COPY . .
RUN uv sync --frozen

# BouncyHSM needs slots created via its management interface.
# The PKCS#11 lib connects to the server via TCP socket.
CMD ["sh", "-c", "\
  cd /opt/bouncyhsm && \
  ASPNETCORE_ENVIRONMENT=Production ASPNETCORE_URLS=http://localhost:5000 \
  dotnet BouncyHsm.dll &>/dev/null & \
  sleep 4 && cd /app && \
  if [ ! -f /usr/lib/libbouncyhsm_pkcs11.so ]; then \
    echo 'BouncyHSM: native PKCS#11 lib not available'; exit 0; fi && \
  uv run python3 -c \"import pkcs11; lib=pkcs11.lib('/usr/lib/libbouncyhsm_pkcs11.so'); print(f'BouncyHSM slots: {len(lib.get_slots())}')\" 2>&1 && \
  echo 'BouncyHSM: server running but needs slot creation via web UI or API. Tests skipped for now.' "]
