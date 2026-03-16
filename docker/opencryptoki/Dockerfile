# OpenCryptoki with SWToken — IBM's PKCS#11 implementation
# v3.0 support, software token backed by OpenSSL

FROM fedora:43

RUN dnf install -y \
    opencryptoki opencryptoki-swtok \
    python3.12 python3.12-devel \
    gcc openssl-devel git \
    && dnf clean all

RUN rpm -q opencryptoki

# OpenCryptoki needs pkcsslotd daemon and proper setup
# Create required directories and users
RUN mkdir -p /var/lib/opencryptoki /var/lock/opencryptoki /var/run/opencryptoki && \
    chmod 770 /var/lib/opencryptoki /var/lock/opencryptoki /var/run/opencryptoki

# Configure SWToken slot
RUN mkdir -p /etc/opencryptoki && \
    printf 'slot 0\n{\nstdll = libswtok.so\n}\n' > /etc/opencryptoki/opencryptoki.conf

# Initialize SWToken
# Default SO PIN: 87654321, User PIN: set via pkcsconf
RUN pkcsslotd 2>/dev/null && sleep 1 && \
    echo "87654321" | pkcsconf -I -c 0 -S 87654321 2>/dev/null && \
    echo "1234" | pkcsconf -P -c 0 -S 87654321 -n 1234 2>/dev/null; \
    killall pkcsslotd 2>/dev/null; true

# Find module
RUN find /usr/lib64 /usr/lib -name "libopencryptoki.so" 2>/dev/null | head -1 > /tmp/module_path && \
    echo "Module: $(cat /tmp/module_path)"

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY . .
RUN uv python pin 3.12 && uv sync --frozen

# OpenCryptoki needs pkcsslotd running
CMD ["sh", "-c", "\
  echo 'OpenCryptoki:' && rpm -q opencryptoki && \
  pkcsslotd && sleep 1 && \
  uv run pytest src/p11test/testcases/ \
    --p11-module=$(cat /tmp/module_path) --p11-pin=1234 -q --tb=no; \
  killall pkcsslotd 2>/dev/null"]
