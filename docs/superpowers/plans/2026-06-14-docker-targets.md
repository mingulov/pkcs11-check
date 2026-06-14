# New Docker Targets (craton-hsm, NetHSM, jcardsim spike) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `craton-hsm` and `nethsm` as PKCS#11 test targets, plus a time-boxed jcardsim/OpenSC build spike, all under the already-shipped run-time `network_mode: none` isolation.

**Architecture:** Each target follows the established `docker/<name>/` pattern. craton is an in-process Rust `.so` (mirrors `docker/kryoptic/Dockerfile.main`). NetHSM co-locates the keyfender server + the Rust `.so` in one image, talking over `127.0.0.1` (mirrors `docker/bouncyhsm/`). jcardsim is validated by a Dockerfile.spike before any full integration.

**Tech Stack:** Docker (compose), Rust/cargo, Python 3.14 + uv, OpenSC `pkcs11-tool`, bash entrypoints.

**Spec:** `docs/superpowers/specs/2026-06-14-docker-targets-design.md` (read it first).

**Validation note (important):** Dockerfile/`.so` correctness can only be fully proven by a real `docker build` + run, which needs **build-time network** and is run in the user's Docker env. Each task therefore has two verification tiers: **(a) static** — `docker compose config -q` / `bash -n` / file presence, runnable here; **(b) build+run** — `./docker/test.sh <name>` producing `artifacts/<name>/report.jsonl`, run by the user. Do NOT commit test statistics to docs (official-release only, per CLAUDE.md).

**Naming:** target `craton-hsm` → service `test-craton-hsm`, dir `docker/craton-hsm/`. Target `nethsm` → service `test-nethsm`, dir `docker/nethsm/`. `docker/test.sh` derives `test-<name>` automatically, so it needs no edit.

---

## Task 1: craton-hsm target (in-process Rust `.so`)

**Files:**
- Create: `docker/craton-hsm/Dockerfile`
- Modify: `docker/docker-compose.test.yml` (add `test-craton-hsm:` service)
- Modify: `docker/test-all.sh:27-37` (add `craton-hsm` to `ALL_PROVIDERS`)
- Modify: `docker/test_pool.py` (add `craton-hsm` to `VARIANT_PROVIDERS` — this is the
  registry the actual pool runner uses; without it the pool will not run the target)
- Modify: `docker/provider-sources.toml` (add `[sources.craton_hsm_main]` + `[targets.craton_hsm]`)

- [ ] **Step 1: Create `docker/craton-hsm/Dockerfile`**

```dockerfile
# craton-hsm-core — pure-Rust PKCS#11 v3.0 software HSM (built from main; no release tags).
# In-process module, no daemon, no network at run time. Mirrors kryoptic/Dockerfile.main
# minus the OpenSSL-from-source stage (craton's default backend is RustCrypto, pure Rust).

FROM rust:latest AS builder

ARG CRATON_REF="main"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "$CRATON_REF" \
    https://github.com/craton-co/craton-hsm-core.git /build/craton
WORKDIR /build/craton
# Build ONLY the root cdylib crate. NOT --workspace: the optional gRPC daemon needs protoc
# and the awslc/fips features need cmake; default features = rustcrypto-backend (what we want).
# If the package name differs, `cargo metadata` / `ls target/release/*.so` reveals the real
# crate; adjust -p and the COPY below accordingly.
RUN cargo build --release -p craton_hsm

FROM python:3.14-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc python3-dev opensc \
    && rm -rf /var/lib/apt/lists/*

# Test tooling: fault-proxy, pkcs11-provider, p11-kit
COPY docker/fault-proxy.c /tmp/fault-proxy.c
COPY docker/install-test-tools.sh /tmp/install-test-tools.sh
RUN bash /tmp/install-test-tools.sh && rm -f /tmp/install-test-tools.sh

COPY --from=builder /build/craton/target/release/libcraton_hsm.so /usr/lib/

# Writable redb-backed token store + a minimal explicit config (lib also has secure
# defaults; we pin the storage path and a single slot).
RUN mkdir -p /var/lib/craton /etc/craton && \
    printf '[token]\nstorage_path = "/var/lib/craton/store"\npersist_objects = true\nslot_count = 1\n' \
    > /etc/craton/craton_hsm.toml
ENV CRATON_HSM_CONFIG=/etc/craton/craton_hsm.toml

# Token init. If --init-token reports no slot, add `--slot 0` (matches slot_count=1).
RUN pkcs11-tool --module /usr/lib/libcraton_hsm.so \
    --init-token --label "pkcs11-check" --so-pin 12345678 && \
    pkcs11-tool --module /usr/lib/libcraton_hsm.so \
    --init-pin --pin 1234 --so-pin 12345678

ENV PKCS11_CHECK_MODULE=/usr/lib/libcraton_hsm.so
ENV PKCS11_CHECK_PIN=1234

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src/pkcs11_check/__init__.py src/pkcs11_check/__init__.py
COPY third_party/ third_party/
RUN uv sync --frozen

COPY . .

CMD ["bash", "/app/docker/run-with-artifacts.sh", "bash", "/app/docker/run-pkcs11-check.sh"]
```

- [ ] **Step 2: Add the compose service** — in `docker/docker-compose.test.yml`, under the "Development branches" section (after `test-corepkcs11-main:`), add:

```yaml
  # craton-hsm-core (main; pure-Rust PKCS#11 v3.0 software HSM)
  test-craton-hsm:
    <<: *common
    build:
      context: ..
      dockerfile: docker/craton-hsm/Dockerfile
      args:
        CRATON_REF: "${CRATON_REF:-main}"
    environment:
      PKCS11_CHECK_ARTIFACT_DIR: /artifacts/craton-hsm
      PKCS11_CHECK_PIN: "1234"
```

(The `<<: *common` merge gives it `network_mode: none` + the volume mounts automatically.)

- [ ] **Step 3: Register the target name in BOTH registries** — the bash sweep and the Python pool runner each keep their own provider list; update both or the pool won't run it.

In `docker/test-all.sh`, add `craton-hsm` to `ALL_PROVIDERS` (next to corepkcs11):
```bash
    corepkcs11 corepkcs11-main
    craton-hsm
```

In `docker/test_pool.py`, add `craton-hsm` to `VARIANT_PROVIDERS` (main-only image, may cold-build-fail and be skipped — same class as `corepkcs11-main`):
```python
VARIANT_PROVIDERS = [
    # ...existing entries...
    "corepkcs11-main",
    "craton-hsm",
]
```
craton is in-process → leave it OUT of `SHARD_MAP` (undivided, 1 shard).

- [ ] **Step 4: Pin the source** — append to `docker/provider-sources.toml`:

```toml
[sources.craton_hsm_main]
kind = "git_branch"
repo = "https://github.com/craton-co/craton-hsm-core.git"
selector = "main"
commit = "d3203bf1f79550a368b5e96a015b9456663080eb"  # 2026-06-07; no release tags exist
commit_date = "2026-06-07T00:00:00Z"

[targets.craton_hsm]
service = "test-craton-hsm"
provider = "Craton HSM (core)"
branch_source = "craton_hsm_main"
openssl = "n/a — RustCrypto default backend (no OpenSSL)"
build_evidence = "main@d3203bf; cargo build --release -p craton_hsm; Apache-2.0; no tags"
```

- [ ] **Step 5: Static validation**

Run: `docker compose -f docker/docker-compose.test.yml config -q && echo OK`
Expected: `OK`. Then confirm isolation + pool registration:
- `uv run pytest tests/test_docker_test_pool.py -q` → all pass. The
  `test_every_compose_service_is_network_isolated` guard now also covers
  `test-craton-hsm` (it must merge `<<: *common`).
- `uv run python -c "import importlib.util; s=importlib.util.spec_from_file_location('p','docker/test_pool.py'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); assert 'craton-hsm' in m.ALL_PROVIDERS"` → no error (pool recognizes it).

- [ ] **Step 6: Commit**

```bash
git add docker/craton-hsm/Dockerfile docker/docker-compose.test.yml docker/test-all.sh docker/test_pool.py docker/provider-sources.toml
git commit -m "docker: add craton-hsm target (pure-Rust in-process PKCS#11, no network)"
```

- [ ] **Step 7: Build + run validation (user's Docker env)**

Run: `./docker/test.sh craton-hsm`
Expected: image builds; `cargo build` produces `libcraton_hsm.so`; `pkcs11-tool --init-token`/`--init-pin` succeed; the suite runs and writes `artifacts/craton-hsm/report.jsonl`. If `cargo build -p craton_hsm` fails on the package name, run `cargo metadata --no-deps --format-version 1 | python3 -c "import json,sys;print([p['name'] for p in json.load(sys.stdin)['packages']])"` to find the cdylib crate and update `-p` + the COPY path. If `--init-token` errors on slot, add `--slot 0`.

---

## Task 2: NetHSM layering build-check (resolve the base-image unknown)

This is a short investigation that picks the Dockerfile base for Task 3. NetHSM's keyfender
server ships in `nitrokey/nethsm:testing`; we need Python+uv+the suite in the same image.

**Files:** none (investigation only; record findings in the Task 3 commit message).

- [ ] **Step 1: Inspect the testing image's base + entrypoint**

Run:
```bash
docker pull nitrokey/nethsm:testing
docker run --rm --entrypoint sh nitrokey/nethsm:testing -c 'cat /etc/os-release; echo ---; which python3 sh bash; echo ---; ls -la /' 2>&1 | head -40
docker inspect nitrokey/nethsm:testing --format '{{json .Config.Entrypoint}} {{json .Config.Cmd}} {{json .Config.ExposedPorts}}'
```
Expected: reveals the distro (apt vs apk vs distroless) and how keyfender is started.

- [ ] **Step 2: Decide the layering** — record one of:
  - **(A) base-on-testing** (preferred): if the image is Debian/Ubuntu/Alpine with a usable
    package manager, the Task 3 Dockerfile uses `FROM nitrokey/nethsm:testing` and installs
    Python+uv on top.
  - **(B) copy-keyfender**: if it is distroless / no package manager, the Task 3 Dockerfile
    uses `FROM python:3.14-slim` and `COPY --from=nitrokey/nethsm:testing` the keyfender
    binary + its required shared libs + `/data` seed. Note the binary path and lib deps
    (`ldd`) discovered here.

Expected output of this task: a one-line decision "(A)" or "(B)" + the keyfender start command + the health endpoint behavior, fed into Task 3.

---

## Task 3: NetHSM target (co-located server + `.so` over loopback)

**Files:**
- Create: `docker/nethsm/Dockerfile`
- Create: `docker/nethsm/run-nethsm.sh`
- Create: `docker/nethsm/p11nethsm.conf`
- Modify: `docker/docker-compose.test.yml` (add `test-nethsm:`)
- Modify: `docker/test-all.sh` (add `nethsm` to `ALL_PROVIDERS`)
- Modify: `docker/test_pool.py` (add `nethsm` to `VARIANT_PROVIDERS`; do NOT add to `SHARD_MAP` initially — keep undivided; coverage is narrow/fast and each shard would re-provision its own server)
- Modify: `docker/provider-sources.toml` (`[sources.nethsm_pkcs11_release]`, `[sources.nethsm_server]`, `[targets.nethsm]`)

- [ ] **Step 1: Create `docker/nethsm/p11nethsm.conf`** (both operator + administrator creds → keygen auto-escalates; insecure cert OK over loopback)

```yaml
# nethsm-pkcs11 config. The module logs in as operator by default and auto-escalates to
# administrator only for actions that need it (e.g. C_GenerateKeyPair) — so the suite can
# generate keys in-process. Co-located server over loopback; self-signed cert accepted.
slots:
  - label: "pkcs11-check"
    operator:
      username: "operator"
      password: "opPassphrase1"
    administrator:
      username: "admin"
      password: "Administrator1"
    instances:
      - url: "https://127.0.0.1:8443/api/v1"
        danger_insecure_cert: true
```

- [ ] **Step 2: Create `docker/nethsm/run-nethsm.sh`** (start keyfender → provision idempotently → create operator → run suite; keys generated by the suite)

```bash
#!/usr/bin/env bash
set -euo pipefail

ADMIN_PASS="Administrator1"
UNLOCK_PASS="UnlockPassphrase1"
OP_USER="operator"
OP_PASS="opPassphrase1"
BASE="https://127.0.0.1:8443/api/v1"

cleanup() { pkill -f keyfender 2>/dev/null || true; }
trap cleanup EXIT

echo "NetHSM: starting keyfender..."
# Start command is the one discovered in Task 2 (binds 0.0.0.0/127.0.0.1:8443).
# Placeholder name 'keyfender'; replace with the actual server invocation from Task 2.
keyfender >/tmp/nethsm-server.log 2>&1 &

# Poll for the REST API (bounded ~30s).
state=""
for _ in $(seq 1 300); do
    state=$(curl -sk "$BASE/health/state" 2>/dev/null | grep -o '"state":"[A-Za-z]*"' | cut -d'"' -f4 || true)
    [[ -n "$state" ]] && break
    sleep 0.1
done
echo "NetHSM: initial state=$state"

if [[ "$state" == "Unprovisioned" ]]; then
    # systemTime is mandatory — NetHSM refuses crypto ops with an unset clock.
    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    curl -sk -X PUT "$BASE/provision" -H "Content-Type: application/json" \
        -d "{\"unlockPassphrase\":\"$UNLOCK_PASS\",\"adminPassphrase\":\"$ADMIN_PASS\",\"systemTime\":\"$now\"}"
    # Wait for Operational.
    for _ in $(seq 1 300); do
        s=$(curl -sk "$BASE/health/state" | grep -o '"state":"[A-Za-z]*"' | cut -d'"' -f4 || true)
        [[ "$s" == "Operational" ]] && break
        sleep 0.1
    done
    # Create the operator user the .so will use (admin-authenticated).
    curl -sk -u "admin:$ADMIN_PASS" -X PUT "$BASE/users/$OP_USER" -H "Content-Type: application/json" \
        -d "{\"realName\":\"pkcs11-check operator\",\"role\":\"Operator\",\"passphrase\":\"$OP_PASS\"}"
fi

export P11NETHSM_CONFIG_FILE=/etc/nitrokey/p11nethsm.conf
export PKCS11_CHECK_MODULE=/usr/lib/libnethsm_pkcs11.so
exec bash /app/docker/run-pkcs11-check.sh
```

- [ ] **Step 3: Create `docker/nethsm/Dockerfile`** — builder stage builds the `.so`; final stage per Task 2's decision. Default shown is option (A):

```dockerfile
# nethsm-pkcs11 module built from a release tag; server consumed from nitrokey/nethsm:testing.
FROM rust:slim AS builder
ARG NETHSM_PKCS11_REF="v2.2.0"
RUN apt-get update && apt-get install -y --no-install-recommends git gcc pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "$NETHSM_PKCS11_REF" \
    https://github.com/Nitrokey/nethsm-pkcs11.git /build/m
WORKDIR /build/m
RUN cargo build --release && test -f target/release/libnethsm_pkcs11.so

# Final stage — option (A): base on the NetHSM testing image (has keyfender).
# If Task 2 chose (B), use `FROM python:3.14-slim` and COPY keyfender + libs from the image.
FROM nitrokey/nethsm:testing

# Install Python toolchain + suite deps. (Adjust package manager per Task 2: apt/apk.)
RUN (apt-get update && apt-get install -y --no-install-recommends python3 python3-dev gcc curl ca-certificates opensc \
     && rm -rf /var/lib/apt/lists/*) \
    || (apk add --no-cache python3 python3-dev gcc curl opensc)

COPY docker/fault-proxy.c /tmp/fault-proxy.c
COPY docker/install-test-tools.sh /tmp/install-test-tools.sh
RUN bash /tmp/install-test-tools.sh && rm -f /tmp/install-test-tools.sh

COPY --from=builder /build/m/target/release/libnethsm_pkcs11.so /usr/lib/
COPY docker/nethsm/p11nethsm.conf /etc/nitrokey/p11nethsm.conf
ENV P11NETHSM_CONFIG_FILE=/etc/nitrokey/p11nethsm.conf
ENV PKCS11_CHECK_MODULE=/usr/lib/libnethsm_pkcs11.so
ENV PKCS11_CHECK_PIN=opPassphrase1

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src/pkcs11_check/__init__.py src/pkcs11_check/__init__.py
COPY third_party/ third_party/
RUN uv sync --frozen
COPY . .

CMD ["bash", "/app/docker/run-with-artifacts.sh", "bash", "/app/docker/nethsm/run-nethsm.sh"]
```

- [ ] **Step 4: Make the run-script executable + add compose service**

```bash
chmod +x docker/nethsm/run-nethsm.sh
```
Add to `docker/docker-compose.test.yml` (Additional/experimental section):

```yaml
  # NetHSM (keyfender server + nethsm-pkcs11 .so, co-located over loopback)
  test-nethsm:
    <<: *common
    build:
      context: ..
      dockerfile: docker/nethsm/Dockerfile
      args:
        NETHSM_PKCS11_REF: "${NETHSM_PKCS11_REF:-v2.2.0}"
    environment:
      PKCS11_CHECK_ARTIFACT_DIR: /artifacts/nethsm
      PKCS11_CHECK_PIN: "opPassphrase1"
```

- [ ] **Step 5: Register the name in BOTH registries** — add `nethsm` to `ALL_PROVIDERS` in `docker/test-all.sh`:

```bash
    bouncyhsm
    nethsm
```
and to `VARIANT_PROVIDERS` in `docker/test_pool.py`:
```python
VARIANT_PROVIDERS = [
    # ...existing entries...
    "craton-hsm",
    "nethsm",
]
```

- [ ] **Step 6: Pin sources** — append to `docker/provider-sources.toml`:

```toml
[sources.nethsm_pkcs11_release]
kind = "git_tag"
repo = "https://github.com/Nitrokey/nethsm-pkcs11.git"
selector = "v2.2.0"
commit_date = "2026-04-23T00:00:00Z"

[sources.nethsm_server]
kind = "docker_image"
repo = "docker.io/nitrokey/nethsm"
selector = "testing"
# Server is image/digest-pinned, NOT source-built: keyfender is an OCaml/MirageOS stack.
# Resolve a digest with `docker manifest inspect` before a release run.

[targets.nethsm]
service = "test-nethsm"
provider = "Nitrokey NetHSM"
release_source = "nethsm_pkcs11_release"
supporting_source = "nethsm_server"
openssl = "n/a — module talks REST to keyfender"
build_evidence = "nethsm-pkcs11 v2.2.0; server nitrokey/nethsm:testing; keygen via admin escalation"
```

- [ ] **Step 7: Static validation**

Run: `bash -n docker/nethsm/run-nethsm.sh && docker compose -f docker/docker-compose.test.yml config -q && echo OK`
Expected: `OK`. Then:
- `uv run pytest tests/test_docker_test_pool.py -q` → all pass (the isolation guard now covers `test-nethsm`).
- `uv run python -c "import importlib.util; s=importlib.util.spec_from_file_location('p','docker/test_pool.py'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); assert 'nethsm' in m.ALL_PROVIDERS"` → no error.

- [ ] **Step 8: Commit**

```bash
git add docker/nethsm/ docker/docker-compose.test.yml docker/test-all.sh docker/test_pool.py docker/provider-sources.toml
git commit -m "docker: add nethsm target (co-located keyfender + nethsm-pkcs11 over loopback)"
```

- [ ] **Step 9: Build + run validation (user's Docker env)**

Run: `./docker/test.sh nethsm`
Expected: image builds; keyfender starts on `127.0.0.1:8443`; provision → Operational; operator created; the suite runs against `libnethsm_pkcs11.so` and writes `artifacts/nethsm/report.jsonl`. **Verify the capability story:** `C_GenerateKeyPair` works (keygen tests run, not skip); `C_Verify`/`C_Digest` tests **skip by capability** (NOT fail). If a verify/digest test *fails* rather than skips, check whether NetHSM advertises `CKF_VERIFY` on a mechanism whose `C_Verify` is stubbed (that is a genuine module self-contradiction → correct `fail`) versus the suite hard-requiring `C_Verify` without a `needs_function` gate (that is a harness gap → file it). Capture the keyfender start command from Task 2 into `run-nethsm.sh` (replace the `keyfender` placeholder).

---

## Task 4: jcardsim / OpenSC build spike (go/no-go, no integration)

**Files:**
- Create: `docker/jcardsim/Dockerfile.spike`
- Create: `docs/findings/jcardsim-spike-2026-06-14.md`

**Do NOT** edit compose/test-all/provider-sources in this task — the spike is gated.

- [ ] **Step 1: Create `docker/jcardsim/Dockerfile.spike`** — a self-contained image that proves the two risky assumptions (build-without-Oracle-SDK; working reader + provisioned key).

```dockerfile
# jcardsim/OpenSC SPIKE — NOT a test target yet. Proves: (1) IsoApplet compiles against the
# jcardsim Maven jar without the Oracle Java Card SDK; (2) the localhost chain
# opensc -> pcscd -> vpcd -> vpicc(jcardsim+IsoApplet) yields a reader + a provisioned key.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates curl default-jdk-headless maven \
    build-essential autoconf automake libtool pkg-config \
    pcscd pcsc-tools opensc libpcsclite-dev \
    && rm -rf /var/lib/apt/lists/*

# vsmartcard (vpcd ifdhandler + vpicc) from source.
RUN git clone --depth 1 --branch virtualsmartcard-0.10 \
    https://github.com/frankmorgner/vsmartcard.git /build/vsmartcard
RUN cd /build/vsmartcard/virtualsmartcard && autoreconf -vis && ./configure && make && make install

# jcardsim jar (Apache-2.0 fork, Maven Central) — avoids the proprietary Oracle SDK.
RUN mkdir -p /opt/jcardsim && cd /opt/jcardsim && \
    curl -fsSL -o jcardsim.jar \
      https://repo1.maven.org/maven2/com/klinec/jcardsim/3.0.5.0/jcardsim-3.0.5.0.jar

# IsoApplet sources; compile straight against the jcardsim jar (NO Oracle SDK).
RUN git clone --depth 1 --branch v0.6.1 https://github.com/philipWendland/IsoApplet.git /build/IsoApplet
RUN mkdir -p /opt/isoapplet && \
    javac -classpath /opt/jcardsim/jcardsim.jar -d /opt/isoapplet \
      $(find /build/IsoApplet/src -name '*.java') && \
    echo "ASSUMPTION 1 PROVEN: IsoApplet compiled against jcardsim jar without Oracle SDK"

COPY docker/jcardsim/run-spike.sh /opt/run-spike.sh
CMD ["bash", "/opt/run-spike.sh"]
```

- [ ] **Step 2: Create `docker/jcardsim/run-spike.sh`** (proves assumption 2; localhost-only)

```bash
#!/usr/bin/env bash
set -uo pipefail
mkdir -p /run/pcscd
pcscd --foreground --disable-polkit >/tmp/pcscd.log 2>&1 &
cat > /tmp/jcardsim.cfg <<'EOF'
com.licel.jcardsim.card.applet.0.AID=F276A288BCFBA69D34F31001
com.licel.jcardsim.card.applet.0.Class=net.pwendland.javacard.pki.isoapplet.IsoApplet
com.licel.jcardsim.vsmartcard.host=localhost
com.licel.jcardsim.vsmartcard.port=35963
EOF
java -cp "/opt/jcardsim/jcardsim.jar:/opt/isoapplet" \
    com.licel.jcardsim.remote.VSmartCard /tmp/jcardsim.cfg >/tmp/jcardsim.log 2>&1 &
for _ in $(seq 1 100); do opensc-tool --list-readers 2>/dev/null | grep -qi "Virtual" && break; sleep 0.2; done
echo "=== readers ==="; opensc-tool --list-readers || true
echo "=== provision (PIN + RSA key) ==="
pkcs15-init --create-pkcs15 --so-pin 12345678 --so-puk 87654321 --pin 1234 --puk 4321 || echo "PROVISION-CREATE-FAILED"
pkcs15-init --generate-key rsa/2048 --auth-id 01 --id 01 --label spike-rsa --pin 1234 || echo "KEYGEN-FAILED"
echo "=== objects via opensc-pkcs11 ==="
pkcs11-tool --module /usr/lib/*/opensc-pkcs11.so -O 2>&1 | head -30 || true
echo "ASSUMPTION 2 RESULT: see whether a reader appeared and a key was generated above"
```

- [ ] **Step 3: Run the spike (user's Docker env)**

```bash
chmod +x docker/jcardsim/run-spike.sh
docker build -f docker/jcardsim/Dockerfile.spike -t jcardsim-spike --network default .
docker run --rm jcardsim-spike
```
Expected: build prints "ASSUMPTION 1 PROVEN"; run shows a "Virtual PCD" reader, a generated RSA key, and `pkcs11-tool -O` listing a private/public key object.

- [ ] **Step 4: Write the go/no-go findings note**

Create `docs/findings/jcardsim-spike-2026-06-14.md` recording: did assumption 1 pass (compile w/o Oracle SDK)? did assumption 2 pass (reader + keygen + objects)? how did a fault surface (JVM exception / `CKR_DEVICE_*` / reader disconnect vs `returncode<0`)? a **GO** (with the concrete `run-jcardsim.sh` + wiring for a follow-up plan) or **NO-GO** (with the blocking reason). Commit:

```bash
git add docker/jcardsim/ docs/findings/jcardsim-spike-2026-06-14.md
git commit -m "docker: jcardsim/OpenSC build spike + go/no-go findings"
```

---

## Final review (after all tasks)

- [ ] `docker compose -f docker/docker-compose.test.yml config -q` passes; `test-craton-hsm` and `test-nethsm` both render `network_mode: none`.
- [ ] `uv run pytest tests/test_docker_test_pool.py -q` passes — the network-isolation guard covers the new services, and both appear in `docker/test_pool.py`'s `ALL_PROVIDERS`.
- [ ] `./docker/test-all.sh` recognizes `craton-hsm` and `nethsm` (e.g. `_is_provider craton-hsm`); `docker/test_pool.py` lists them in `VARIANT_PROVIDERS`.
- [ ] No statistics committed to docs. No existing target regressed (only additive files + the isolation anchor already verified).
- [ ] jcardsim remains spike-only unless the findings note says GO.
