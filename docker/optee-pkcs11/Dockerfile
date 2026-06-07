# OP-TEE PKCS#11 QEMU target.
#
# Build args:
#   OPTEE_REF       OP-TEE manifest branch/tag

FROM debian:trixie

ARG OPTEE_REF="4.10.0"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    android-sdk-libsparse-utils \
    autoconf \
    automake \
    bc \
    bison \
    build-essential \
    ca-certificates \
    ccache \
    cpio \
    curl \
    device-tree-compiler \
    expect \
    file \
    flex \
    gawk \
    gcc-aarch64-linux-gnu \
    gcc-arm-linux-gnueabihf \
    git \
    libgnutls28-dev \
    libglib2.0-dev \
    libpixman-1-dev \
    libssl-dev \
    libtool \
    make \
    ninja-build \
    pkg-config \
    python-is-python3 \
    python3 \
    python3-cryptography \
    python3-pip \
    python3-pyelftools \
    python3-venv \
    rsync \
    unzip \
    uuid-dev \
    wget \
    xz-utils \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://storage.googleapis.com/git-repo-downloads/repo \
    -o /usr/local/bin/repo && \
    chmod +x /usr/local/bin/repo

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /optee
RUN repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml -b "$OPTEE_REF" && \
    repo sync -j"$(nproc)" --no-clone-bundle

RUN make -C build -j"$(nproc)" toolchains

RUN make -C build \
    -j"$(nproc)" \
    CFG_PKCS11_TA=y \
    CFG_PKCS11_TA_ALLOW_DIGEST_KEY=y \
    CFG_PKCS11_TA_AUTH_TEE_IDENTITY=y \
    CFG_PKCS11_TA_CHECK_VALUE_ATTRIBUTE=y \
    CFG_PKCS11_TA_RSA_X_509=y \
    CFG_PKCS11_TA_HEAP_SIZE='(128 * 1024)' \
    QEMU_VIRTFS_ENABLE=y \
    QEMU_PSS_ENABLE=y \
    RUST_ENABLE=n \
    BR2_PACKAGE_PYTHON3=y \
    BR2_PACKAGE_PYTHON3_PYEXPAT=y \
    BR2_PACKAGE_PYTHON3_ZLIB=y \
    BR2_PACKAGE_OPENSC=y \
    all

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY LICENSE-APACHE LICENSE-MIT THIRD_PARTY_LICENSES.md ./
COPY src/ src/
COPY third_party/ third_party/
COPY docker/optee-pkcs11/build-guest-site.sh docker/optee-pkcs11/build-guest-site.sh
RUN bash docker/optee-pkcs11/build-guest-site.sh /opt/pkcs11-check-site

COPY . .

RUN chmod +x \
    /app/docker/optee-pkcs11/build-guest-site.sh \
    /app/docker/optee-pkcs11/salvage-artifacts.py \
    /app/docker/optee-pkcs11/run-optee-pkcs11.sh \
    /app/docker/optee-pkcs11/optee-pkcs11.exp

ENV PKCS11_CHECK_MODULE=/usr/lib/libckteec.so
ENV PKCS11_CHECK_PIN=1234
ENV PKCS11_CHECK_SO_PIN=87654321
ENV PKCS11_CHECK_SLOT=0
ENV PKCS11_CHECK_INTERFACE=2.40

CMD ["bash", "/app/docker/run-with-artifacts.sh", "bash", "/app/docker/optee-pkcs11/run-optee-pkcs11.sh"]
