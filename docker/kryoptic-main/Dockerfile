# Kryoptic main — latest development (no FIPS, default features)

FROM rust:latest AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git pkg-config libssl-dev clang make \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/latchset/kryoptic.git /build/kryoptic
WORKDIR /build/kryoptic
RUN cargo build --release 2>&1 | tail -3

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 git gcc python3-dev libssl-dev opensc \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/kryoptic/target/release/libkryoptic_pkcs11.so /usr/lib/

RUN mkdir -p /var/lib/kryoptic /etc/kryoptic && \
    printf '[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "/var/lib/kryoptic/token.sql"\n' \
    > /etc/kryoptic/token.conf
ENV KRYOPTIC_CONF=/etc/kryoptic/token.conf

RUN pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
    --init-token --label "p11test" --so-pin 12345678 && \
    pkcs11-tool --module /usr/lib/libkryoptic_pkcs11.so \
    --init-pin --pin 1234 --so-pin 12345678

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY . .
RUN uv sync --frozen

CMD ["sh", "-c", "echo 'Kryoptic main (latest dev):' && uv run pytest src/p11test/testcases/ --p11-module=/usr/lib/libkryoptic_pkcs11.so --p11-pin=1234 -q --tb=no"]
