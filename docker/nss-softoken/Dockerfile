# NSS softoken test image
# Uses Fedora for latest NSS with potential PQC patches
# Use Fedora Rawhide for latest NSS with PKCS#11 v3.2 PQC support
FROM fedora:rawhide

# Install NSS and tools
RUN dnf install -y \
    nss nss-tools nss-softokn \
    python3.12 python3.12-devel \
    gcc openssl-devel git \
    && dnf clean all

# Show NSS version
RUN nss-config --version 2>/dev/null || rpm -q nss

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Initialize NSS database with a token
ENV NSS_DB_DIR=/var/lib/nss
RUN mkdir -p $NSS_DB_DIR && \
    certutil -d sql:$NSS_DB_DIR -N --empty-password && \
    echo "1234" > /tmp/pin.txt && \
    modutil -dbdir sql:$NSS_DB_DIR -changepw "NSS Certificate DB" -pwfile /dev/null -newpwfile /tmp/pin.txt 2>/dev/null; \
    rm -f /tmp/pin.txt

# Find the softoken module
RUN find /usr/lib64 /usr/lib -name "libsoftokn3.so" 2>/dev/null | head -1 > /tmp/module_path && \
    echo "Module: $(cat /tmp/module_path)"

WORKDIR /app

# Copy and install project
COPY . .

# Use python3.12 explicitly on Fedora
RUN uv python pin 3.12 && uv sync --frozen

# NSS softoken requires the NSS DB directory to be set
ENV NSS_DEFAULT_DB_DIR=sql:$NSS_DB_DIR

# NSS softoken works without PIN for most operations
CMD ["sh", "-c", "echo 'NSS version:' && rpm -q nss && echo 'Module:' && cat /tmp/module_path && uv run pytest src/p11test/testcases/ --p11-module=$(cat /tmp/module_path) -q --tb=no"]
