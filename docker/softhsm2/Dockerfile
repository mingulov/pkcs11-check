# Stage 1: Build SoftHSM2 2.7.0
FROM python:3.12-slim AS softhsm-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git make g++ libssl-dev libsqlite3-dev \
    automake autoconf autoconf-archive libtool pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch 2.7.0 https://github.com/softhsm/SoftHSMv2.git /build/softhsm2
WORKDIR /build/softhsm2
RUN sh autogen.sh \
    && ./configure --prefix=/usr --sysconfdir=/etc \
       --with-crypto-backend=openssl --disable-gost \
       --disable-dependency-tracking \
    && make -j$(nproc) \
    && make DESTDIR=/install install

# Stage 2: Runtime with tests
FROM python:3.12-slim

# Copy only the built SoftHSM2 binaries + libs (no build tools)
COPY --from=softhsm-builder /install/usr /usr

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libsqlite3-0 git gcc python3-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set up token
ENV SOFTHSM2_CONF=/etc/softhsm2.conf
RUN mkdir -p /var/lib/softhsm/tokens && \
    echo "directories.tokendir = /var/lib/softhsm/tokens" > $SOFTHSM2_CONF && \
    echo "objectstore.backend = file" >> $SOFTHSM2_CONF && \
    softhsm2-util --init-token --slot 0 --label "pkcs11-check" --pin 1234 --so-pin 12345678

RUN find /usr/lib -name "libsofthsm2.so" | head -1 > /tmp/module_path
ENV PKCS11_CHECK_PIN=1234

WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy and install everything
# Install deps first (cached unless pyproject.toml/uv.lock/python-pkcs11 change)
COPY pyproject.toml uv.lock ./
COPY python-pkcs11/ python-pkcs11/
ENV SETUPTOOLS_SCM_PRETEND_VERSION_FOR_PYTHON_PKCS11=0.0
RUN uv sync --frozen

# Copy test code (changes frequently, does not invalidate deps cache)
COPY . .

CMD ["bash", "/app/docker/run-with-artifacts.sh", "sh", "-c", "softhsm2-util --version && export PKCS11_CHECK_MODULE=$(cat /tmp/module_path) && bash /app/docker/run-pkcs11-check.sh"]
