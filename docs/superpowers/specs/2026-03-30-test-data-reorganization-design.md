# Test Data Reorganization Design

**Date:** 2026-03-30
**Status:** Approved
**Scope:** Move third-party test vector repos out of `src/`, replace git submodules with download script, Docker bind-mount

## Problem

Third-party test vector data (1.1 GB across 4 git submodules) lives inside
`src/pkcs11_check/testcases/data/`, creating several issues:

1. **Package contamination risk** — data is inside the importable package tree; `hatch build` could pull it into wheels
2. **Git clone bloat** — `--recurse-submodules` downloads 1.1 GB; submodule UX is painful
3. **Docker image bloat** — `COPY . .` pulls wycheproof (103 MB) and cctv (3.8 MB) into every image
4. **Mixed ownership** — third-party repos intermixed with project source code
5. **Inconsistent fetch** — `.gitmodules` registers all 4, `fetch-optional-data.sh` covers only 2, comments contradict reality

## Design

### Directory structure

```
data/                                       # NEW: root dir (NOT fully gitignored)
  sources.toml                              # TRACKED — manifest: pins, checksums, URLs
  .gitignore                                # TRACKED — ignores extracted dirs only
  wycheproof/                               # gitignored, extracted from GitHub archive
    testvectors_v1/                         # 336 JSON files, ~102 MB
    LICENSE
  cctv/                                     # gitignored, extracted from GitHub archive
    ed25519/                                # ~3.8 MB total
    ML-DSA/
    RFC6979/
    ...
  acvp/                                     # gitignored, extracted from GitHub archive
    gen-val/json-files/                     # 161 algorithm dirs, ~613 MB
    README.md                               # license info
    ...                                     # rest of repo included (no sparse)
  x509-limbo/                              # gitignored, extracted from GitHub archive
    limbo.json                              # ~73 MB total
    ...

src/pkcs11_check/testcases/data/           # UNCHANGED: own data stays here
  __init__.py                               # updated: vendor paths point to root data/
  mechanism_vectors/                         # our curated KAT vectors (236 KB, tracked)
  sha1.json, sha256.json, ...              # our KAT data (tracked)
  aes_ecb.json
```

### Manifest file (`data/sources.toml`)

Tracked in git — the single source of truth for what to fetch and how to verify it.
The script reads this file; humans update it when upgrading to newer upstream versions.

```toml
# Third-party test vector sources.
# Run: bash scripts/fetch-data.sh [name|all|--status]
# Update: change commit + archive_sha256, then re-fetch.

[wycheproof]
repo = "C2SP/wycheproof"
commit = "78898104021ebd2cd98820e4112da89b1531d999"
archive_sha256 = "<sha256-of-github-archive-zip>"
description = "Wycheproof edge-case cryptographic test vectors"
include = ["testvectors_v1/", "LICENSE"]

[cctv]
repo = "C2SP/CCTV"
commit = "d091f096c98eaaf9a42a824eb923a457867e4eae"
archive_sha256 = "<sha256-of-github-archive-zip>"
description = "C2SP Comprehensive Cryptographic Test Vectors"
include = ["ed25519/", "ML-DSA/", "ML-KEM/", "RFC6979/", "jq255/", "keygen/", "README.md", "LICENSE"]

[acvp]
repo = "usnistgov/ACVP-Server"
commit = "3611942ea10c070dd8bc6afec5682d56c307de8a"
archive_sha256 = "<sha256-of-github-archive-zip>"
description = "NIST ACVP Automated Cryptographic Validation"
include = ["gen-val/json-files/", "README.md"]

[x509-limbo]
repo = "C2SP/x509-limbo"
commit = "9d594748cd0184468ec80a2d6e69d231ecf9fc8f"
archive_sha256 = "<sha256-of-github-archive-zip>"
description = "C2SP x509-limbo pathological X.509 certificates"
# No include = extract everything (repo is 73 MB, all useful)
```

Fields:
- `commit` — full 40-char git hash, pinned for reproducibility
- `archive_sha256` — SHA-256 of the GitHub archive zip at that commit (integrity check)
- `repo` — used to construct `https://github.com/{repo}/archive/{commit}.zip`
- `include` — optional list of paths to extract (directories end with `/`).
  When present, only matching paths are extracted. When absent, everything is extracted.
  Paths are relative to the archive root (after stripping the GitHub `{repo}-{commit}/` prefix).
- Updating a source: change `commit` + `archive_sha256`, commit the TOML, re-run fetch

### Download script (`scripts/fetch-data.sh`)

Replaces `scripts/fetch-optional-data.sh`. Reads `data/sources.toml` for pins and
checksums. Uses GitHub archive downloads — no git required.

```bash
bash scripts/fetch-data.sh all           # fetch everything
bash scripts/fetch-data.sh wycheproof    # just wycheproof
bash scripts/fetch-data.sh acvp          # just ACVP
bash scripts/fetch-data.sh --status      # show what's present/missing
```

Mechanism per source (driven by `data/sources.toml`):
1. Read `repo`, `commit`, `archive_sha256`, `include` from `data/sources.toml` (via Python `tomllib`)
2. `curl -sL https://github.com/{repo}/archive/{commit}.zip -o /tmp/{name}.zip`
3. Verify SHA-256: `sha256sum /tmp/{name}.zip` against `archive_sha256` from manifest
4. Extract to temp dir, strip GitHub's top-level `{repo}-{commit}/` prefix
5. If `include` is set, copy only matching paths; otherwise copy everything
6. Move to `data/{name}/`
7. Clean up temp files

The `include` filter means ACVP extracts only `gen-val/json-files/` + `README.md` (~613 MB)
instead of the full repo (927 MB), saving 314 MB of C# source code.

No git clone, no submodules, no sparse checkout. Just HTTP download + unzip + filter + verify.

### Data resolver (`data/__init__.py`)

Updated to resolve third-party data from root `data/` directory:

```python
"""Centralized test data paths — single source of truth."""
from __future__ import annotations

import os
from pathlib import Path

# Own data (tracked in git, part of the package)
DATA_DIR = Path(__file__).parent
KAT_DIR = DATA_DIR

# Third-party vendor data (root data/, fetched by scripts/fetch-data.sh)
def _find_project_root() -> Path:
    """Walk up to find pyproject.toml (project root marker)."""
    p = Path(__file__).resolve().parent
    while p != p.parent:
        if (p / "pyproject.toml").exists():
            return p
        p = p.parent
    return Path.cwd()

_VENDOR_DIR = Path(os.environ.get(
    "PKCS11_CHECK_DATA_DIR",
    str(_find_project_root() / "data"),
))

WYCHEPROOF_DIR = _VENDOR_DIR / "wycheproof" / "testvectors_v1"
CCTV_DIR = _VENDOR_DIR / "cctv"
ACVP_DIR = _VENDOR_DIR / "acvp" / "gen-val" / "json-files"
X509_LIMBO_DIR = _VENDOR_DIR / "x509-limbo"
```

- `PKCS11_CHECK_DATA_DIR` env var overrides the default for CI/Docker/worktrees
- All existing imports (`from pkcs11_check.testcases.data import WYCHEPROOF_DIR`) keep working
- `mechanism_vectors.py` is unchanged — its `_VECTOR_DIR` still points within `src/`

### Test skip behavior

Already works — existing patterns check path existence:

```python
# acvp_loader.py — already does this
ACVP_AVAILABLE = ACVP_DIR.exists()

# wycheproof tests — already do this
if not (WYCHEPROOF_DIR / "aes_gcm_test.json").exists():
    pytest.skip("Wycheproof vectors not available")
```

If `data/` doesn't exist or a specific source isn't fetched, tests skip cleanly.

### Docker: bind-mount instead of copy

**docker-compose.test.yml** — add shared read-only volume:

```yaml
x-data: &data
  volumes:
    - ../data:/app/data:ro

x-artifacts: &artifacts
  volumes:
    - ../artifacts:/artifacts

services:
  test-softhsm2:
    <<: [*artifacts, *data]
    ...
```

**`.dockerignore`** — add:
```
data/
```

**`docker/test.sh`** — warn if `data/` is empty or missing:
```bash
if [ ! -d "$PROJECT_ROOT/data" ]; then
    echo "Warning: data/ not found. Run: bash scripts/fetch-data.sh all"
fi
```

Benefits:
- Docker images contain only code + PKCS#11 module (no test data baked in)
- All 12 Docker targets share one host-side `data/` directory
- Data fetched once on host, mounted read-only into containers
- Faster builds — no 100+ MB of data in build context

### Cleanup: remove git submodules

1. Delete `.gitmodules` file
2. Remove submodule sections from `.git/config`
3. Remove submodule cache dirs from `.git/modules/`
4. `git rm` the current `src/pkcs11_check/testcases/data/{wycheproof,cctv,acvp,x509-limbo}/` dirs
5. Delete `scripts/fetch-optional-data.sh` (replaced by `scripts/fetch-data.sh`)
6. Create `data/sources.toml` (manifest, tracked)
7. Create `data/.gitignore` (ignores extracted dirs, tracked)
8. Add `data/` exclusion to `.dockerignore`

### Git tracking strategy

`data/` is NOT fully gitignored. Two files inside are tracked:

**`data/.gitignore`** (tracked):
```gitignore
# Extracted third-party data (fetched by scripts/fetch-data.sh)
# Only sources.toml and this .gitignore are tracked.
wycheproof/
cctv/
acvp/
x509-limbo/
```

**`data/sources.toml`** (tracked): the manifest described above.

This means `git clone` gives you the manifest + gitignore, and `bash scripts/fetch-data.sh all`
populates the actual data. Clean, explicit, version-controlled pins.

### .dockerignore additions

`.dockerignore` does NOT honor `.gitignore` — it needs its own exclusion.
Docker doesn't need any of `data/` since it's bind-mounted at runtime:

```dockerignore
# Third-party test vector data (bind-mounted at runtime, not copied)
data/
```

### Integration points

| Component | Change needed |
|-----------|--------------|
| `data/sources.toml` | New: manifest with pins + checksums (tracked) |
| `data/.gitignore` | New: ignores extracted dirs (tracked) |
| `scripts/fetch-data.sh` | New: replaces `scripts/fetch-optional-data.sh` |
| `data/__init__.py` | Update vendor paths to root `data/` |
| `mechanism_vectors.py` | None (own data, stays in `src/`) |
| `acvp_loader.py` | None (imports `ACVP_DIR` from `data/__init__`) |
| wycheproof loaders | None (import `WYCHEPROOF_DIR` from `data/__init__`) |
| cctv test files | None (import `CCTV_DIR` from `data/__init__`) |
| x509 conftest | None (imports `X509_LIMBO_DIR` from `data/__init__`) |
| `docker-compose.test.yml` | Add `data/:ro` volume mount |
| `.dockerignore` | Add `data/` |
| `.gitmodules` | Delete entirely |
| `scripts/fetch-optional-data.sh` | Delete (replaced) |
| `local-builds/test.sh` | Optional: warn if data missing |
| `docker/test.sh` | Optional: warn if data missing |
| `CLAUDE.md` | Update data directory references |

### Future: zip-as-runtime (Option B)

This design supports a later evolution to store zip archives instead of extracted
directories. The only change would be in `data/__init__.py` — swap `pathlib.Path`
to `zipfile.Path` and add a small glob shim. All downstream code stays the same
since it imports paths from `data/__init__.py`.

Measured compression ratios (actual):
- wycheproof: 102 MB → 24 MB (4.3x)
- cctv: 3.8 MB → 1.3 MB (2.9x)
- acvp json-only: 613 MB → 306 MB (2.0x)

Total savings: ~792 MB → ~346 MB. Worth revisiting if disk footprint becomes a concern.

## Non-goals

- Changing test vector loading patterns (loaders stay the same)
- Adding new test vector sources (separate task)
- Modifying `mechanism_vectors/` or KAT data (own data, unaffected)
- Implementing zip-as-runtime now (deferred to future)
