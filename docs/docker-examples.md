# Running pkcs11-check in Docker

Self-contained, copy-pasteable container examples that need no local install and no
source build - both `pkcs11-check` (from PyPI) and SoftHSM2 (from a distro package
manager) are installed inside the image. SoftHSM2 is a pure-software PKCS#11 provider,
so these need no hardware. For the host (non-Docker) walkthrough, see
[getting-started-softhsm2.md](getting-started-softhsm2.md).

## Single-version quickstart (SoftHSM2 on Ubuntu)

The same install -> token -> run flow as the host walkthrough, packaged in a container.
Everything comes from a package manager - there is no source build.

```dockerfile
# Save as Dockerfile, then build:  docker build -t pkcs11-check-softhsm2 .
FROM ubuntu:24.04

# SoftHSM2 (PKCS#11 provider + token tool) and Python, both from apt.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv softhsm2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install pkcs11-check from PyPI into a venv (Ubuntu's system Python is PEP-668
# "externally managed"). Pin a version (pkcs11-check==0.1.6) for a reproducible image.
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir pkcs11-check

# Create a SoftHSM2 config and one token (user PIN 1234, SO/admin PIN 5678).
ENV SOFTHSM2_CONF=/etc/softhsm2.conf
RUN mkdir -p /var/lib/softhsm/tokens /out \
    && printf 'directories.tokendir = /var/lib/softhsm/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' > "$SOFTHSM2_CONF" \
    && softhsm2-util --init-token --free --label demo --pin 1234 --so-pin 5678

# The module path varies by architecture; resolve it once.
RUN find /usr/lib -name libsofthsm2.so | head -n1 > /etc/pkcs11-module-path

# Default run: a quick offline subset; JSON written to /out (mount it to keep results).
CMD ["bash","-lc","pkcs11-check test --module \"$(cat /etc/pkcs11-module-path)\" --pin 1234 --slot 0 --match 'test_encrypt or test_sign or test_digest' --output json --output-file /out/results.json"]
```

Build the image, then run it with a host directory mapped onto `/out` so the reports
persist after the container exits:

```bash
docker build -t pkcs11-check-softhsm2 .

# Map a host ./reports dir onto /out. On SELinux hosts (Fedora/RHEL) add :z -> /out:z
docker run --rm -v "$PWD/reports:/out" pkcs11-check-softhsm2

ls reports/        # results.json  report.jsonl  coverage.json  quality.json
cat reports/results.json
```

The default command writes JSON to `/out/results.json` (alongside `report.jsonl`,
`coverage.json`, and `quality.json`). Without the `-v` mount the run still prints a
console summary, but the files stay inside the removed container - the bind mount is
how the results reach the host. Files written through the mount are owned by `root`
(the container runs as root); run `sudo chown -R "$USER" reports/` if that matters.

To run the **full** suite instead, fetch the vector data and drop the `--match` filter
(this needs network and downloads ~800 MB):

```bash
docker run --rm -v "$PWD/reports:/out" pkcs11-check-softhsm2 \
  bash -lc 'pkcs11-check fetch-data all && \
            pkcs11-check test --module "$(cat /etc/pkcs11-module-path)" --pin 1234 --slot 0 \
                --output json --output-file /out/results.json'
```

## Compare two SoftHSM2 versions

`pkcs11-check` can diff two result sets, so you can ask "did upgrading the provider
change anything?". Ubuntu and Debian package only SoftHSM2 2.6.1, so this example uses
Fedora, which packages 2.6.1 (Fedora 43) and 2.7.0 (Fedora 44). Fedora 44's 2.7.0 is a
release candidate - fine for demonstrating the comparison.

One Dockerfile serves both versions; only the base image changes:

```dockerfile
# Save as Dockerfile.compare. Build once per version (commands below).
ARG BASE=fedora:43
FROM ${BASE}

RUN dnf install -y python3 python3-pip softhsm && dnf clean all

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir pkcs11-check

ENV SOFTHSM2_CONF=/etc/softhsm2.conf
RUN mkdir -p /var/lib/softhsm/tokens /out \
    && printf 'directories.tokendir = /var/lib/softhsm/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' > "$SOFTHSM2_CONF" \
    && softhsm2-util --init-token --free --label demo --pin 1234 --so-pin 5678

# Fedora keeps the module under /usr/lib64; search both to stay distro-agnostic.
RUN find /usr/lib64 /usr/lib -name libsofthsm2.so | head -n1 > /etc/pkcs11-module-path

# Broader OFFLINE profile so coverage.json is substantive. The marker flag is --marker
# (in this CLI -m is --module, not the marker expression).
CMD ["bash","-lc","pkcs11-check test --module \"$(cat /etc/pkcs11-module-path)\" --pin 1234 --slot 0 --marker 'not (wycheproof or acvp or cctv or stress or fuzz or slow)' --output json --output-file /out/results.json"]
```

Build both versions, run each into its own directory, then compare (add `:z` to the
mounts on SELinux hosts):

```bash
docker build -f Dockerfile.compare --build-arg BASE=fedora:43 -t pk-sh-2.6 .   # SoftHSM2 2.6.1
docker build -f Dockerfile.compare --build-arg BASE=fedora:44 -t pk-sh-2.7 .   # SoftHSM2 2.7.0-rc

docker run --rm -v "$PWD/cmp/v2.6:/out" pk-sh-2.6
docker run --rm -v "$PWD/cmp/v2.7:/out" pk-sh-2.7

# Compare 2.6.1 (baseline) against 2.7.0 (candidate); exits non-zero if it regressed.
pkcs11-check compare-results  cmp/v2.6/results.json  cmp/v2.7/results.json
pkcs11-check compare-coverage cmp/v2.6/coverage.json cmp/v2.7/coverage.json
```

`compare-results` reports new failures, lost target coverage, and failure/crash-count
changes (`-v` for per-target detail; `--no-fail` to report without a non-zero exit).
`compare-coverage` reports mechanism-coverage states gained or lost (`--fail-on-loss`
to exit non-zero on any loss). `pkcs11-check` runs on the host here (installed per
[getting-started-softhsm2.md](getting-started-softhsm2.md) step 1).

If you only used Docker and don't have `pkcs11-check` on the host, run the comparison
inside either image (it already has the tool), mounting the results read-only:

```bash
docker run --rm -v "$PWD/cmp:/cmp:ro" pk-sh-2.7 \
  pkcs11-check compare-results  /cmp/v2.6/results.json  /cmp/v2.7/results.json
docker run --rm -v "$PWD/cmp:/cmp:ro" pk-sh-2.7 \
  pkcs11-check compare-coverage /cmp/v2.6/coverage.json /cmp/v2.7/coverage.json
```
