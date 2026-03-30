# Docker Image Modernization Design

**Date:** 2026-03-30
**Status:** Approved
**Scope:** Python 3.14, shared test tools (fault-proxy + pkcs11-provider + p11-kit), platform-aware detection, .dockerignore cleanup

## Problem

1. **Skipped tests in Docker runs** — fault-proxy (6 tests), pkcs11-provider (3 tests), p11-kit (3 tests) are not installed in any Docker image, causing 12 skips per run across all modules
2. **Python 3.12** — Debian-based images use `python:3.12-slim`, now outdated
3. **Hardcoded Debian paths** — `test_interop_openssl.py` uses `/usr/lib/x86_64-linux-gnu/...` paths that don't exist on Fedora images
4. **Build context bloat** — `docs/`, `tests/`, `scripts/`, `.claude/`, investigation reports all copied into every image (~5 MB of unnecessary files, some containing dev-only content)

## Design

### Python 3.14 base images

- Debian-based images: `python:3.12-slim` → `python:3.14-slim`
- **Note:** `python:3.14-slim` uses Debian Trixie (13), not Bookworm (12). This is a
  Debian major version change. `pkcs11-provider` is available in Trixie but NOT Bookworm,
  so this upgrade is actually required for the pkcs11-provider install to work on Debian.
- Fedora-based images: unchanged (Fedora 43 ships Python 3.13, Fedora 44 ships 3.14 natively)
- `pyproject.toml` `target-version` stays at `"py311"` — project minimum unchanged

Affected Dockerfiles (Debian-based):
- `docker/softhsm2/Dockerfile` (2 FROM lines)
- `docker/kryoptic/Dockerfile` (1 FROM line)
- `docker/kryoptic/Dockerfile.main` (1 FROM line)
- `docker/bouncyhsm/Dockerfile` (1 FROM line)

### Shared test tools script (`docker/install-test-tools.sh`)

A single distro-aware script that installs fault-proxy, pkcs11-provider, and p11-kit.
Each Dockerfile adds 2-3 lines to invoke it. No base image dependency chain.

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
    fedora) dnf install -y p11-kit ;;  # proxy module is in base p11-kit on Fedora
esac

# --- pkcs11-provider (OpenSSL 3.x PKCS#11 provider) ---
case $DISTRO in
    debian) apt-get install -y --no-install-recommends pkcs11-provider ;;
    fedora) dnf install -y pkcs11-provider || true ;;  # not available on all Fedora versions
esac

# --- fault-proxy (compile from bundled source) ---
# The .c file is COPY'd into /tmp/ by each Dockerfile before this script runs.
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

#### Fault-proxy source location

**IMPORTANT:** `local-builds/` is excluded by `.dockerignore`, so `COPY local-builds/fault-proxy/fault-proxy.c`
would fail. The fault-proxy C source must be copied to a Docker-accessible location first:

```
docker/fault-proxy.c    # copy of local-builds/fault-proxy/fault-proxy.c, tracked in git
```

This is a 326-line C file (~10 KB). Keeping a copy under `docker/` avoids `.dockerignore` conflicts.

#### Integration into each Dockerfile

Each Dockerfile adds these lines in its runtime stage, after system deps are installed
(including `gcc`) and before the `uv sync` / `COPY . .` layer:

```dockerfile
# Test tooling: fault-proxy, pkcs11-provider, p11-kit
COPY docker/fault-proxy.c /tmp/fault-proxy.c
COPY docker/install-test-tools.sh /tmp/install-test-tools.sh
RUN bash /tmp/install-test-tools.sh && rm -f /tmp/install-test-tools.sh
```

All 15 Dockerfiles already have `gcc` in their runtime stage (verified), so fault-proxy
compiles in-place. No builder-stage workaround needed.

#### Package availability matrix

| Package | Debian (python:3.14-slim) | Fedora 43 | Fedora 44 |
|---------|--------------------------|-----------|-----------|
| p11-kit | `apt: p11-kit` | `dnf: p11-kit` | `dnf: p11-kit` |
| pkcs11-provider | `apt: pkcs11-provider` | `dnf: pkcs11-provider` | `dnf: pkcs11-provider` |
| fault-proxy | compiled from source | compiled from source | compiled from source |
| gcc | needs `apt install gcc` | already present (build deps) | already present |

### Platform-aware library detection

Fix hardcoded Debian paths in test files to check multiple platform paths.

**`test_interop_openssl.py`** — replace:
```python
def _have_pkcs11_provider() -> bool:
    return Path("/usr/lib/x86_64-linux-gnu/ossl-modules/pkcs11.so").exists()
```

With:
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

def _find_pkcs11_provider() -> Path | None:
    return _find_lib(_PKCS11_PROVIDER_PATHS)

def _find_p11kit_proxy() -> Path | None:
    return _find_lib(_P11KIT_PROXY_PATHS)
```

**`test_ckr_fault_inject.py` and `test_ckr_universal.py`** — update fault-proxy path:
```python
_FAULT_PROXY_PATHS = [
    Path(__file__).parents[4] / "local-builds" / "fault-proxy" / "fault-proxy.so",  # local dev
    Path("/usr/lib/pkcs11/fault-proxy.so"),                                           # Docker
]

_PROXY_PATH = next((p for p in _FAULT_PROXY_PATHS if p.exists()), None)
```

### `.dockerignore` cleanup

Add these exclusions to reduce build context and avoid leaking dev files:

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
*.txt
CLAUDE.md
AGENTS.md
prd.md
INVESTIGATION*.md
```

**Preserved in build context** (needed by containers):
- `src/pkcs11_check/` — all testcase source code
- `docker/run-with-artifacts.sh`, `docker/run-pkcs11-check.sh` — container CMD entrypoints
- `docker/<provider>/run-*.sh` — provider-specific startup scripts
- `pyproject.toml`, `uv.lock`, `README.md` — package metadata
- `docker/fault-proxy.c` — compiled inside container
- `docker/install-test-tools.sh` — shared install script
- `data/sources.toml`, `data/.gitignore` — manifest (data itself is bind-mounted)

### Integration points

| Component | Change needed |
|-----------|--------------|
| `docker/install-test-tools.sh` | New: shared distro-aware install script |
| `docker/softhsm2/Dockerfile` | `python:3.14-slim`, add test tools install, fault-proxy compile |
| `docker/kryoptic/Dockerfile` | `python:3.14-slim`, add test tools install |
| `docker/kryoptic/Dockerfile.main` | `python:3.14-slim`, add test tools install |
| `docker/bouncyhsm/Dockerfile` | `python:3.14-slim`, add test tools install |
| `docker/nss-softoken/Dockerfile` | Add test tools install (Fedora, no Python change) |
| `docker/nss-softoken/Dockerfile.rawhide` | Add test tools install |
| `docker/nss-softoken/Dockerfile.main` | Add test tools install |
| `docker/opencryptoki/Dockerfile` | Add test tools install |
| `docker/opencryptoki/Dockerfile.master` | Add test tools install |
| `docker/pkcs11-mock/Dockerfile` | Add test tools install |
| `docker/qryptotoken/Dockerfile` | Add test tools install |
| `docker/softhsm2/Dockerfile.main` | Add test tools install |
| `docker/kryoptic/Dockerfile.fips` | Add test tools install |
| `docker/tpm2-pkcs11/Dockerfile` | Add test tools install |
| `docker/nss-softoken/Dockerfile.stable` | Add test tools install (orphan, near-identical to main) |
| `src/pkcs11_check/testcases/test_interop_openssl.py` | Platform-aware lib detection (both detection AND usage sites) |
| `src/pkcs11_check/testcases/ckr/test_ckr_fault_inject.py` | Multi-path fault-proxy detection |
| `src/pkcs11_check/testcases/ckr/test_ckr_universal.py` | Multi-path fault-proxy detection |
| `.dockerignore` | Add docs/, scripts/, tests/, .claude/, Dockerfile patterns |

### Expected impact

- **12 previously-skipped tests now run** in all Docker targets (6 fault-proxy + 3 pkcs11-provider + 3 p11-kit)
- **Build context reduced** by ~5 MB per image (docs, tests, scripts, dev files excluded)
- **Python 3.14** in 4 Debian-based images (performance, newer stdlib)
- **No dev files leak** into container images (investigation reports, CLAUDE.md, etc.)

### Known issues to address during implementation

1. **`test_load_module_via_p11kit` uses `import pkcs11`** — the `python-pkcs11` library is
   not a project dependency. This test has a pre-existing ImportError bug. Fix: rewrite
   to use `pkcs11_check.raw` API instead of the removed `python-pkcs11` library.

2. **`test_load_module_via_p11kit` hardcoded path at line ~130** — uses the Debian p11-kit
   path as a string argument to `pkcs11.lib()`, not just for detection. Must use the
   `_find_p11kit_proxy()` result here too.

3. **tpm2-pkcs11 p11-kit interaction** — p11-kit auto-discovers PKCS#11 modules. In the
   tpm2 container, this could interact with `tpm2-abrmd` daemon startup. Test carefully
   after adding p11-kit to the tpm2 image.

## Non-goals

- Changing `pyproject.toml` Python minimum version (stays at 3.11)
- Creating a shared base Docker image (using shell script approach instead)
- Adding other interop test dependencies beyond these three
- Modifying Fedora version pins (stay on 43/44)
