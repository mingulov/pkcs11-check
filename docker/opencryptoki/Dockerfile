# OpenCryptoki with SWToken — IBM's PKCS#11 implementation
# v3.0 support, software token backed by OpenSSL
#
# Architecture: pkcsslotd daemon must be running, user must be in 'pkcs11' group.
# In Docker we run as root and start pkcsslotd at CMD time (not build time,
# since the daemon does not persist across RUN layers).

FROM fedora:43

RUN dnf install -y \
    opencryptoki opencryptoki-swtok \
    python3.12 python3.12-devel \
    gcc openssl-devel git \
    && dnf clean all

RUN rpm -q opencryptoki opencryptoki-swtok

# OpenCryptoki runtime directories (group-writable; root runs fine in Docker)
RUN mkdir -p /var/lib/opencryptoki /var/lock/opencryptoki /var/run/opencryptoki && \
    chmod 770 /var/lib/opencryptoki /var/lock/opencryptoki /var/run/opencryptoki

# Configure SWToken slot — override /etc/opencryptoki/opencryptoki.conf
# The stdll name on Fedora is libswtok.so (no path prefix needed; opencryptoki
# searches its own slot directory automatically).
RUN mkdir -p /etc/opencryptoki && \
    printf 'version 1\nslot 0\n{\nstdll = libswtok.so\n}\n' \
    > /etc/opencryptoki/opencryptoki.conf

# The PKCS#11 module that applications load (not the slot stdll).
# This is the stable, well-known path on Fedora.
ENV P11TEST_MODULE=/usr/lib64/pkcs11/libopencryptoki.so

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY . .
RUN uv python pin 3.12 && uv sync --frozen

# Initialization happens at CMD time because pkcsslotd must be alive.
# Flow:
#   1. Start daemon
#   2. Wait for socket/slot enumeration
#   3. Initialize slot 0 (SO PIN: 87654321)
#   4. Set user PIN (1234)
#   5. Run tests
#   6. Kill daemon on exit
CMD ["sh", "-c", "\
  echo 'OpenCryptoki:' && rpm -q opencryptoki opencryptoki-swtok && \
  pkcsslotd && sleep 2 && \
  echo '87654321' | pkcsconf -I -c 0 -S 87654321 2>&1 || true && \
  echo '87654321' | pkcsconf -P -c 0 -S 87654321 -n 1234 2>&1 || true && \
  pkcsconf -s 2>&1 || true && \
  uv run pytest src/p11test/testcases/ \
    --p11-module=/usr/lib64/pkcs11/libopencryptoki.so \
    --p11-pin=1234 -q --tb=short; \
  RC=$? && killall pkcsslotd 2>/dev/null; exit $RC"]
