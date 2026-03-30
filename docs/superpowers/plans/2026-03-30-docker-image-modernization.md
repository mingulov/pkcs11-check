# Docker Image Modernization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add fault-proxy, pkcs11-provider, and p11-kit to all Docker images; upgrade Debian images to Python 3.14; fix hardcoded library paths; clean up .dockerignore.

**Architecture:** A shared `docker/install-test-tools.sh` script detects Debian vs Fedora and installs the three components. Each Dockerfile adds 3 lines to invoke it. Test detection code is updated to check multiple platform paths. `.dockerignore` is tightened to exclude docs/tests/scripts.

**Tech Stack:** Bash, Docker, Python (test detection)

**Spec:** `docs/superpowers/specs/2026-03-30-docker-image-modernization-design.md`

**Model guidance:** Use Sonnet for Tasks 1, 2, 4-6 (file creation, mechanical Dockerfile edits). Use Opus for Task 3 (test detection changes — requires understanding test patterns) and Task 7 (verification).

---

### Task 1: Create shared test tools script and fault-proxy copy

**Files:**
- Create: `docker/install-test-tools.sh`
- Create: `docker/fault-proxy.c` (copy from `local-builds/fault-proxy/fault-proxy.c`)

- [ ] **Step 1: Copy fault-proxy.c to docker/**

```bash
cp local-builds/fault-proxy/fault-proxy.c docker/fault-proxy.c
```

Verify: `diff local-builds/fault-proxy/fault-proxy.c docker/fault-proxy.c` — no diff.

- [ ] **Step 2: Create `docker/install-test-tools.sh`**

Write this exact content:

```bash
#!/usr/bin/env bash
# Install shared test tooling (fault-proxy, pkcs11-provider, p11-kit)
# for pkcs11-check Docker images. Handles Debian (apt) and Fedora (dnf).
set -euo pipefail

# --- Detect distro ---
if command -v apt-get &>/dev/null; then
    DISTRO=debian
elif command -v dnf &>/dev/null; then
    DISTRO=fedora
else
    echo "WARNING: Unknown distro, skipping test tool install" >&2
    exit 0
fi

# --- p11-kit ---
case $DISTRO in
    debian) apt-get update && apt-get install -y --no-install-recommends \
                p11-kit p11-kit-modules ;;
    fedora) dnf install -y p11-kit ;;
esac

# --- pkcs11-provider (OpenSSL 3.x PKCS#11 provider) ---
case $DISTRO in
    debian) apt-get install -y --no-install-recommends pkcs11-provider ;;
    fedora) dnf install -y pkcs11-provider || true ;;
esac

# --- fault-proxy (compile from bundled source) ---
if [ -f /tmp/fault-proxy.c ]; then
    mkdir -p /usr/lib/pkcs11
    gcc -shared -fPIC -o /usr/lib/pkcs11/fault-proxy.so /tmp/fault-proxy.c -ldl
    rm -f /tmp/fault-proxy.c
    echo "fault-proxy.so installed to /usr/lib/pkcs11/"
fi

# --- Cleanup ---
case $DISTRO in
    debian) rm -rf /var/lib/apt/lists/* ;;
    fedora) dnf clean all ;;
esac
```

- [ ] **Step 3: Make executable**

```bash
chmod +x docker/install-test-tools.sh
```

- [ ] **Step 4: Commit**

```bash
git add docker/fault-proxy.c docker/install-test-tools.sh
git commit -m "feat(docker): add shared test tools install script and fault-proxy source"
```

---

### Task 2: Update .dockerignore

**Files:**
- Modify: `.dockerignore`

- [ ] **Step 1: Read current .dockerignore**

Read `.dockerignore` to see current content.

- [ ] **Step 2: Append new exclusions**

Add these lines to the END of `.dockerignore`:

```dockerignore

# Documentation — not needed at runtime
docs/

# Host-side scripts (fetch-data, analysis, etc.)
scripts/

# Meta-tests (pkcs11-check's own tests, not product testcases)
tests/

# Claude Code / editor state
.claude/

# Dockerfiles and compose (not needed inside containers; run-*.sh ARE needed)
docker/*/Dockerfile*
docker/docker-compose*.yml

# Root analysis/investigation/dev files
CLAUDE.md
AGENTS.md
prd.md
INVESTIGATION*.md
```

Do NOT add `*.txt` — too broad.

- [ ] **Step 3: Verify no needed files are excluded**

Run: `docker compose -f docker/docker-compose.test.yml config --services`
Expected: still lists all services (compose file isn't used from inside the container).

- [ ] **Step 4: Commit**

```bash
git add .dockerignore
git commit -m "chore(docker): exclude docs, scripts, tests, dev files from build context"
```

---

### Task 3: Fix platform-aware library detection in test files

**Files:**
- Modify: `src/pkcs11_check/testcases/test_interop_openssl.py`
- Modify: `src/pkcs11_check/testcases/ckr/test_ckr_fault_inject.py`
- Modify: `src/pkcs11_check/testcases/ckr/test_ckr_universal.py`

This is the most complex task — requires understanding the test patterns and
fixing both detection and usage of library paths.

- [ ] **Step 1: Fix `test_interop_openssl.py` detection functions**

Replace the two single-path detection functions (lines 25-32) with platform-aware versions:

```python
_PKCS11_PROVIDER_PATHS = [
    "/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so",  # Debian x86_64
    "/usr/lib64/ossl-modules/pkcs11.so",                   # Fedora/RHEL x86_64
    "/usr/lib/ossl-modules/pkcs11.so",                     # Fedora multilib
]

_P11KIT_PROXY_PATHS = [
    "/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so",         # Debian x86_64
    "/usr/lib64/p11-kit-proxy.so",                          # Fedora/RHEL x86_64
    "/usr/lib/p11-kit-proxy.so",                            # Fedora multilib
]


def _find_lib(candidates: list[str]) -> Path | None:
    """Find the first existing library path from candidates."""
    for c in candidates:
        p = Path(c)
        if p.exists():
            return p
    return None


def _have_pkcs11_provider() -> bool:
    """Check if OpenSSL pkcs11-provider is installed."""
    return _find_lib(_PKCS11_PROVIDER_PATHS) is not None


def _have_p11kit() -> bool:
    """Check if p11-kit proxy is installed."""
    return _find_lib(_P11KIT_PROXY_PATHS) is not None
```

- [ ] **Step 2: Fix hardcoded proxy path in `test_load_module_via_p11kit`**

In `test_load_module_via_p11kit` (around line 130), the hardcoded path
`"/usr/lib/x86_64-linux-gnu/p11-kit-proxy.so"` is used as a function argument.
Also, the test uses `import pkcs11` which is a removed dependency. Rewrite the
test to use `pkcs11_check.raw` API instead.

Replace the entire `test_load_module_via_p11kit` method with:

```python
    def test_load_module_via_p11kit(self, p11_config: Any) -> None:
        """Load our module through p11-kit-proxy - must not crash."""
        proxy_path = _find_lib(_P11KIT_PROXY_PATHS)
        if proxy_path is None:
            pytest.skip("p11-kit not installed")

        # Use raw PKCS#11 API via subprocess to avoid crash contamination
        script = textwrap.dedent(f"""\
            from pkcs11_check.raw.api import RawPKCS11
            try:
                raw = RawPKCS11.from_lib("{proxy_path}")
                raw.C_Initialize()
                print("OK: p11-kit proxy loaded and initialized")
                raw.C_Finalize()
            except Exception as e:
                print(f"ERROR: {{type(e).__name__}}: {{e}}")
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"p11-kit proxy crashed (rc={result.returncode}): {result.stderr}"
        )
        assert "OK:" in result.stdout or "ERROR:" in result.stdout
```

- [ ] **Step 3: Fix `test_ckr_fault_inject.py` proxy path**

Replace line 22:
```python
_PROXY_PATH = Path(__file__).parents[4] / "local-builds" / "fault-proxy" / "fault-proxy.so"
```

With:
```python
_FAULT_PROXY_PATHS = [
    Path(__file__).parents[4] / "local-builds" / "fault-proxy" / "fault-proxy.so",
    Path("/usr/lib/pkcs11/fault-proxy.so"),
]

_PROXY_PATH = next((p for p in _FAULT_PROXY_PATHS if p.exists()), None)
```

Also update `_skip_if_no_proxy()` (lines 25-28) since `_PROXY_PATH` can now be `None`:
```python
def _skip_if_no_proxy() -> None:
    """Skip if fault-proxy.so is not built."""
    if _PROXY_PATH is None or not _PROXY_PATH.exists():
        pytest.skip(
            "fault-proxy not built (run: bash local-builds/build.sh fault-proxy)"
        )
```

And update all `str(_PROXY_PATH)` usages — they still work since `_PROXY_PATH`
is a `Path` when found, and `_skip_if_no_proxy()` skips when it's `None`.

- [ ] **Step 4: Fix `test_ckr_universal.py` proxy path**

Find the `test_device_removed_via_fault_proxy` method (around line 152). Replace
the local proxy path lookup:

```python
        proxy = Path(__file__).parents[4] / "local-builds" / "fault-proxy" / "fault-proxy.so"
        if not proxy.exists():
            pytest.skip("fault-proxy not built")
```

With:
```python
        proxy_candidates = [
            Path(__file__).parents[4] / "local-builds" / "fault-proxy" / "fault-proxy.so",
            Path("/usr/lib/pkcs11/fault-proxy.so"),
        ]
        proxy = next((p for p in proxy_candidates if p.exists()), None)
        if proxy is None:
            pytest.skip("fault-proxy not built")
```

- [ ] **Step 5: Run linting**

Run: `uv run ruff check src/pkcs11_check/testcases/test_interop_openssl.py src/pkcs11_check/testcases/ckr/test_ckr_fault_inject.py src/pkcs11_check/testcases/ckr/test_ckr_universal.py`
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/testcases/test_interop_openssl.py \
        src/pkcs11_check/testcases/ckr/test_ckr_fault_inject.py \
        src/pkcs11_check/testcases/ckr/test_ckr_universal.py
git commit -m "fix(tests): platform-aware detection for pkcs11-provider, p11-kit, fault-proxy"
```

---

### Task 4: Upgrade Debian-based Dockerfiles to Python 3.14-slim

**Files:**
- Modify: `docker/softhsm2/Dockerfile`
- Modify: `docker/kryoptic/Dockerfile`
- Modify: `docker/kryoptic/Dockerfile.main`
- Modify: `docker/bouncyhsm/Dockerfile`

- [ ] **Step 1: Update python base image tags**

In each file, replace `python:3.12-slim` with `python:3.14-slim`:

- `docker/softhsm2/Dockerfile`: 2 occurrences (lines 2 and 19)
- `docker/kryoptic/Dockerfile`: 1 occurrence
- `docker/kryoptic/Dockerfile.main`: 1 occurrence
- `docker/bouncyhsm/Dockerfile`: 1 occurrence

Use `replace_all` for each file to replace `python:3.12-slim` → `python:3.14-slim`.

- [ ] **Step 2: Verify no other 3.12 references remain**

Run: `grep -r "python:3.12" docker/`
Expected: no matches

- [ ] **Step 3: Commit**

```bash
git add docker/softhsm2/Dockerfile docker/kryoptic/Dockerfile \
        docker/kryoptic/Dockerfile.main docker/bouncyhsm/Dockerfile
git commit -m "feat(docker): upgrade Debian-based images to python:3.14-slim (Trixie)"
```

---

### Task 5: Add test tools to Debian-based Dockerfiles

**Files:**
- Modify: `docker/softhsm2/Dockerfile`
- Modify: `docker/kryoptic/Dockerfile`
- Modify: `docker/kryoptic/Dockerfile.main`
- Modify: `docker/bouncyhsm/Dockerfile`

For each Dockerfile, add the test tools install lines AFTER the `apt-get install`
block (which provides gcc) and BEFORE the `WORKDIR /app` line. The exact insertion
varies per Dockerfile, so read each one first.

- [ ] **Step 1: Read each Dockerfile and add test tools lines**

The 3 lines to add in each Debian Dockerfile, after the `apt-get install ... gcc ...`
and `rm -rf /var/lib/apt/lists/*` block:

```dockerfile
# Test tooling: fault-proxy, pkcs11-provider, p11-kit
COPY docker/fault-proxy.c /tmp/fault-proxy.c
COPY docker/install-test-tools.sh /tmp/install-test-tools.sh
RUN bash /tmp/install-test-tools.sh && rm -f /tmp/install-test-tools.sh
```

Insert BEFORE the `WORKDIR /app` or `COPY --from=ghcr.io/astral-sh/uv` line.

For `docker/softhsm2/Dockerfile`: after line 26 (after `rm -rf /var/lib/apt/lists/*`),
before line 28 (`# Set up token`).

For other Debian Dockerfiles: similar position — after runtime deps install, before
token setup or uv install.

- [ ] **Step 2: Commit**

```bash
git add docker/softhsm2/Dockerfile docker/kryoptic/Dockerfile \
        docker/kryoptic/Dockerfile.main docker/bouncyhsm/Dockerfile
git commit -m "feat(docker): add test tools to Debian-based images"
```

---

### Task 6: Add test tools to Fedora-based Dockerfiles

**Files:**
- Modify: `docker/nss-softoken/Dockerfile`
- Modify: `docker/nss-softoken/Dockerfile.rawhide`
- Modify: `docker/nss-softoken/Dockerfile.main`
- Modify: `docker/nss-softoken/Dockerfile.stable`
- Modify: `docker/opencryptoki/Dockerfile`
- Modify: `docker/opencryptoki/Dockerfile.master`
- Modify: `docker/pkcs11-mock/Dockerfile`
- Modify: `docker/qryptotoken/Dockerfile`
- Modify: `docker/softhsm2/Dockerfile.main`
- Modify: `docker/kryoptic/Dockerfile.fips`
- Modify: `docker/tpm2-pkcs11/Dockerfile`

Same pattern as Task 5, but for Fedora images. Each needs the same 3 lines
inserted after the `dnf install` block that provides gcc:

```dockerfile
# Test tooling: fault-proxy, pkcs11-provider, p11-kit
COPY docker/fault-proxy.c /tmp/fault-proxy.c
COPY docker/install-test-tools.sh /tmp/install-test-tools.sh
RUN bash /tmp/install-test-tools.sh && rm -f /tmp/install-test-tools.sh
```

- [ ] **Step 1: Read each Fedora Dockerfile and find the insertion point**

For each Dockerfile, read it, find the `dnf install` block that includes `gcc`,
and add the test tools lines AFTER it and BEFORE token setup or uv install.

Some Fedora Dockerfiles are single-stage (nss-softoken, opencryptoki, pkcs11-mock,
qryptotoken, tpm2-pkcs11). Some are multi-stage (nss-softoken/Dockerfile.rawhide,
nss-softoken/Dockerfile.main, opencryptoki/Dockerfile.master, softhsm2/Dockerfile.main,
kryoptic/Dockerfile.fips). For multi-stage, add the lines in the RUNTIME stage
(the second FROM), not the builder.

- [ ] **Step 2: Add test tools to all 11 Fedora Dockerfiles**

Insert the 3 lines in each file at the identified position.

- [ ] **Step 3: Commit**

```bash
git add docker/nss-softoken/Dockerfile docker/nss-softoken/Dockerfile.rawhide \
        docker/nss-softoken/Dockerfile.main docker/nss-softoken/Dockerfile.stable \
        docker/opencryptoki/Dockerfile docker/opencryptoki/Dockerfile.master \
        docker/pkcs11-mock/Dockerfile docker/qryptotoken/Dockerfile \
        docker/softhsm2/Dockerfile.main docker/kryoptic/Dockerfile.fips \
        docker/tpm2-pkcs11/Dockerfile
git commit -m "feat(docker): add test tools to Fedora-based images"
```

---

### Task 7: Build verification

**Files:** None — verification only.

- [ ] **Step 1: Build a Debian image to verify test tools install**

Run: `docker compose -f docker/docker-compose.test.yml build test-softhsm2 2>&1 | tail -20`
Expected: build succeeds, shows "fault-proxy.so installed to /usr/lib/pkcs11/"

- [ ] **Step 2: Verify test tools are present in the image**

Run:
```bash
docker compose -f docker/docker-compose.test.yml run --rm --no-deps --entrypoint bash \
    test-softhsm2 -c "ls -la /usr/lib/pkcs11/fault-proxy.so && \
    find / -name 'pkcs11.so' -path '*/ossl-modules/*' 2>/dev/null && \
    find / -name 'p11-kit-proxy.so' 2>/dev/null"
```
Expected: all three files found.

- [ ] **Step 3: Build a Fedora image to verify**

Run: `docker compose -f docker/docker-compose.test.yml build test-nss 2>&1 | tail -20`
Expected: build succeeds.

- [ ] **Step 4: Verify Fedora test tools**

Run:
```bash
docker compose -f docker/docker-compose.test.yml run --rm --no-deps --entrypoint bash \
    test-nss -c "ls -la /usr/lib/pkcs11/fault-proxy.so && \
    find / -name 'pkcs11.so' -path '*/ossl-modules/*' 2>/dev/null && \
    find / -name 'p11-kit-proxy.so' 2>/dev/null"
```
Expected: all three files found (paths will differ from Debian).

- [ ] **Step 5: Run a quick Docker test to verify the 12 tests now run**

Run:
```bash
bash docker/test.sh softhsm2 -- \
    src/pkcs11_check/testcases/test_interop_openssl.py \
    src/pkcs11_check/testcases/ckr/test_ckr_fault_inject.py -v
```
Expected: interop and fault-inject tests run (not skipped). Some may pass, some
may fail with real module issues — the key is they don't skip with "not installed".

- [ ] **Step 6: Run linting and meta-tests**

Run: `uv run ruff check src/ tests/ && uv run python -m pytest tests/ -q`
Expected: both pass.
