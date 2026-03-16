FROM python:3.12-slim

# Build SoftHSM2 2.7.0 from source (distro packages are 2.6.1)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake g++ libssl-dev libsqlite3-dev automake autoconf libtool pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch 2.7.0 https://github.com/softhsm/SoftHSMv2.git /build/softhsm2 \
    && cd /build/softhsm2 \
    && sh autogen.sh \
    && ./configure --prefix=/usr --sysconfdir=/etc --with-crypto-backend=openssl \
    && make -j$(nproc) \
    && make install \
    && rm -rf /build/softhsm2

# Set up SoftHSM2 token
ENV SOFTHSM2_CONF=/etc/softhsm2.conf
ENV TOKEN_DIR=/var/lib/softhsm/tokens
RUN mkdir -p $TOKEN_DIR && \
    echo "directories.tokendir = $TOKEN_DIR" > $SOFTHSM2_CONF && \
    echo "objectstore.backend = file" >> $SOFTHSM2_CONF && \
    softhsm2-util --init-token --slot 0 --label "p11test" --pin 1234 --so-pin 12345678

# Find and export module path
RUN find /usr/lib -name "libsofthsm2.so" | head -1 > /tmp/module_path
ENV P11TEST_PIN=1234

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

COPY . .
RUN uv sync --frozen

CMD ["sh", "-c", "softhsm2-util --version && uv run pytest src/p11test/testcases/ --p11-module=$(cat /tmp/module_path) --p11-pin=1234 -v"]
