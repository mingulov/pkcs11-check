# Test Data Reorganization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move third-party test vector data from `src/` to root `data/`, replace git submodules with a manifest-driven download script, and bind-mount data in Docker instead of copying.

**Architecture:** A tracked manifest (`data/sources.toml`) pins commit hashes and SHA-256 checksums for 4 upstream repos. A bash script reads the manifest, downloads GitHub archive zips, verifies checksums, and extracts only the paths listed in `include`. The Python data resolver (`data/__init__.py`) is updated to find vendor data at the new root `data/` location. Docker compose gets a read-only bind-mount instead of baking data into images.

**Tech Stack:** Bash (fetch script), Python `tomllib` (manifest parsing), TOML (manifest format), Docker Compose volumes

**Spec:** `docs/superpowers/specs/2026-03-30-test-data-reorganization-design.md`

**Model guidance:** Use Sonnet 4.6 for Tasks 1-4 (file creation, config edits). Use Opus 4.6 for Task 5 (fetch script — the most complex piece).

---

### Task 1: Create manifest and data directory scaffold

**Files:**
- Create: `data/sources.toml`
- Create: `data/.gitignore`

- [ ] **Step 1: Create `data/.gitignore`**

```gitignore
# Extracted third-party data (fetched by scripts/fetch-data.sh)
# Only sources.toml and this .gitignore are tracked.
wycheproof/
cctv/
acvp/
x509-limbo/
```

- [ ] **Step 2: Create `data/sources.toml` with placeholder checksums**

```toml
# Third-party test vector sources — single source of truth for fetch-data.sh.
# Run:    bash scripts/fetch-data.sh [name|all|--status]
# Update: change commit + archive_sha256, then re-fetch.

[wycheproof]
repo = "C2SP/wycheproof"
commit = "78898104021ebd2cd98820e4112da89b1531d999"
archive_sha256 = "PLACEHOLDER"
description = "Wycheproof edge-case cryptographic test vectors"
include = ["testvectors_v1/", "LICENSE"]

[cctv]
repo = "C2SP/CCTV"
commit = "d091f096c98eaaf9a42a824eb923a457867e4eae"
archive_sha256 = "PLACEHOLDER"
description = "C2SP Comprehensive Cryptographic Test Vectors"
include = ["ed25519/", "ML-DSA/", "ML-KEM/", "RFC6979/", "jq255/", "keygen/", "README.md", "LICENSE"]

[acvp]
repo = "usnistgov/ACVP-Server"
commit = "3611942ea10c070dd8bc6afec5682d56c307de8a"
archive_sha256 = "PLACEHOLDER"
description = "NIST ACVP Automated Cryptographic Validation"
include = ["gen-val/json-files/", "README.md"]

[x509-limbo]
repo = "C2SP/x509-limbo"
commit = "9d594748cd0184468ec80a2d6e69d231ecf9fc8f"
archive_sha256 = "PLACEHOLDER"
description = "C2SP x509-limbo pathological X.509 certificates"
# No include = extract everything
```

- [ ] **Step 3: Verify `data/` dir exists with both files**

Run: `ls -la data/`
Expected: `sources.toml` and `.gitignore` present

- [ ] **Step 4: Commit scaffold**

```bash
git add data/sources.toml data/.gitignore
git commit -m "feat(data): add manifest and gitignore for test vector data"
```

---

### Task 2: Update data resolver to use root `data/`

**Files:**
- Modify: `src/pkcs11_check/testcases/data/__init__.py`

- [ ] **Step 1: Replace `data/__init__.py` contents**

Replace the entire file with:

```python
"""Centralized test data paths — single source of truth.

Own data (mechanism_vectors, KAT JSONs) lives here in src/.
Third-party vendor data lives in root data/, fetched by scripts/fetch-data.sh.
"""
from __future__ import annotations

import os
from pathlib import Path

# Own data (tracked in git, part of the package)
DATA_DIR = Path(__file__).parent
KAT_DIR = DATA_DIR


def _find_project_root() -> Path:
    """Walk up to find pyproject.toml (project root marker)."""
    p = Path(__file__).resolve().parent
    while p != p.parent:
        if (p / "pyproject.toml").exists():
            return p
        p = p.parent
    return Path.cwd()


# Third-party vendor data (root data/, fetched by scripts/fetch-data.sh)
# Override with PKCS11_CHECK_DATA_DIR env var for CI/Docker/worktrees.
_VENDOR_DIR = Path(os.environ.get(
    "PKCS11_CHECK_DATA_DIR",
    str(_find_project_root() / "data"),
))

WYCHEPROOF_DIR = _VENDOR_DIR / "wycheproof" / "testvectors_v1"
CCTV_DIR = _VENDOR_DIR / "cctv"
ACVP_DIR = _VENDOR_DIR / "acvp" / "gen-val" / "json-files"
X509_LIMBO_DIR = _VENDOR_DIR / "x509-limbo"
```

- [ ] **Step 2: Run linting and type check**

Run: `uv run ruff check src/pkcs11_check/testcases/data/__init__.py`
Expected: no errors

Run: `uv run mypy src/pkcs11_check/testcases/data/__init__.py`
Expected: passes (may warn about module-level code)

- [ ] **Step 3: Verify imports still work**

Run: `uv run python -c "from pkcs11_check.testcases.data import WYCHEPROOF_DIR, CCTV_DIR, ACVP_DIR, X509_LIMBO_DIR, KAT_DIR, DATA_DIR; print('OK:', WYCHEPROOF_DIR)"`
Expected: prints OK and a path like `/.../pkcs11-check/data/wycheproof/testvectors_v1`

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/testcases/data/__init__.py
git commit -m "feat(data): update resolver to find vendor data in root data/"
```

---

### Task 3: Update `.dockerignore` and Docker Compose

**Files:**
- Modify: `.dockerignore`
- Modify: `docker/docker-compose.test.yml`

- [ ] **Step 1: Add `data/` to `.dockerignore`**

Add at the top of `.dockerignore`, replacing the old submodule exclusions:

```dockerignore
# Third-party test vector data (bind-mounted at runtime, not copied)
data/
```

Remove the now-obsolete lines:
```
src/pkcs11_check/testcases/data/acvp/
src/pkcs11_check/testcases/data/x509-limbo/
```

The full `.dockerignore` should become:

```dockerignore
# Third-party test vector data (bind-mounted at runtime, not copied)
data/

# Local builds (large, not needed in Docker)
local-builds/

# Virtual environments (host venv must not leak into container)
.venv/

# Worktrees
.worktrees/

# Git internals
.git/
python-pkcs11/.git/

# Python caches
**/__pycache__/
*.pyc
.mypy_cache/
.pytest_cache/
.ruff_cache/

# Artifacts from previous Docker runs
artifacts/
```

- [ ] **Step 2: Add data bind-mount to `docker-compose.test.yml`**

Add a new YAML anchor after the existing `x-artifacts` anchor:

```yaml
x-data: &data
  volumes:
    - ../data:/app/data:ro
```

Then update every service to merge both anchors. For each service, change `<<: *artifacts` to merge both. Since YAML merge key `<<` doesn't support lists directly in all compose versions, the safest approach is to add the data volume to the existing artifacts anchor:

Replace the existing `x-artifacts` block:

```yaml
x-artifacts: &artifacts
  volumes:
    - ../artifacts:/artifacts
```

With a combined block:

```yaml
x-common: &common
  volumes:
    - ../artifacts:/artifacts
    - ../data:/app/data:ro
```

Then update every `<<: *artifacts` reference to `<<: *common` across all services (15 services total).

- [ ] **Step 3: Verify compose file parses**

Run: `docker compose -f docker/docker-compose.test.yml config --services`
Expected: lists all 15 services without error

- [ ] **Step 4: Commit**

```bash
git add .dockerignore docker/docker-compose.test.yml
git commit -m "feat(docker): bind-mount data/ read-only, remove old submodule excludes"
```

---

### Task 4: Remove git submodules

**Files:**
- Delete: `.gitmodules`
- Delete: `scripts/fetch-optional-data.sh`
- Modify: `.git/config` (submodule sections)
- Delete: `.git/modules/src/pkcs11_check/testcases/data/*`
- Delete: `src/pkcs11_check/testcases/data/{wycheproof,cctv,acvp,x509-limbo}/`

This task removes all 4 git submodules. The submodule data currently at
`src/pkcs11_check/testcases/data/{name}` is deleted from git tracking.
After this task, `bash scripts/fetch-data.sh all` (Task 5) will repopulate
the data at `data/{name}` instead.

- [ ] **Step 1: Deinit all submodules**

```bash
git submodule deinit -f src/pkcs11_check/testcases/data/wycheproof
git submodule deinit -f src/pkcs11_check/testcases/data/cctv
git submodule deinit -f src/pkcs11_check/testcases/data/acvp
git submodule deinit -f src/pkcs11_check/testcases/data/x509-limbo
```

This removes the submodule entries from `.git/config` and cleans the working tree.

- [ ] **Step 2: Remove submodules from git index**

```bash
git rm -f src/pkcs11_check/testcases/data/wycheproof
git rm -f src/pkcs11_check/testcases/data/cctv
git rm -f src/pkcs11_check/testcases/data/acvp
git rm -f src/pkcs11_check/testcases/data/x509-limbo
```

- [ ] **Step 3: Delete `.gitmodules`**

```bash
git rm .gitmodules
```

- [ ] **Step 4: Remove cached submodule metadata**

```bash
rm -rf .git/modules/src/pkcs11_check/testcases/data/wycheproof
rm -rf .git/modules/src/pkcs11_check/testcases/data/cctv
rm -rf .git/modules/src/pkcs11_check/testcases/data/acvp
rm -rf .git/modules/src/pkcs11_check/testcases/data/x509-limbo
rm -rf .git/modules/src/pkcs11_check/testcases/vectors
```

Note: the wycheproof submodule had a stale name `testcases/vectors/wycheproof` in
`.gitmodules`, so check both paths.

- [ ] **Step 5: Delete old fetch script**

```bash
git rm scripts/fetch-optional-data.sh
```

- [ ] **Step 6: Verify clean state**

Run: `git submodule status`
Expected: no output (no submodules registered)

Run: `git status`
Expected: staged deletions for `.gitmodules`, `fetch-optional-data.sh`, and the 4 submodule paths. No unexpected changes.

- [ ] **Step 7: Commit**

```bash
git commit -m "refactor(data): remove all git submodules (replaced by data/sources.toml)"
```

---

### Task 5: Create `scripts/fetch-data.sh`

**Files:**
- Create: `scripts/fetch-data.sh`

This is the most complex task. The script reads `data/sources.toml` using a Python
one-liner (via `tomllib`), downloads GitHub archive zips, verifies SHA-256, extracts
selectively based on `include`, and strips the GitHub prefix directory.

- [ ] **Step 1: Create the fetch script**

```bash
#!/usr/bin/env bash
# Fetch third-party test vector data from GitHub archives.
# Reads data/sources.toml for pinned commits, checksums, and include filters.
#
# Usage:
#   bash scripts/fetch-data.sh all           # fetch everything
#   bash scripts/fetch-data.sh wycheproof    # just one source
#   bash scripts/fetch-data.sh --status      # show what's present/missing
#   bash scripts/fetch-data.sh --checksums   # download and print SHA-256 (for updating sources.toml)

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

MANIFEST="data/sources.toml"
DATA_DIR="data"

if [ ! -f "$MANIFEST" ]; then
    echo "ERROR: $MANIFEST not found. Are you in the project root?" >&2
    exit 1
fi

# Parse a source entry from sources.toml via Python tomllib.
# Usage: _parse_source <name> <field>
# Returns the value of sources[name][field], or empty string if missing.
_parse_source() {
    local name="$1" field="$2"
    uv run python -c "
import tomllib, sys, json
with open('$MANIFEST', 'rb') as f:
    sources = tomllib.load(f)
src = sources.get('$name', {})
val = src.get('$field', '')
if isinstance(val, list):
    print(json.dumps(val))
else:
    print(val)
"
}

# Get all source names from the manifest.
_list_sources() {
    uv run python -c "
import tomllib
with open('$MANIFEST', 'rb') as f:
    sources = tomllib.load(f)
for name in sources:
    print(name)
"
}

# Show status of each source (present/missing).
_show_status() {
    echo "Test vector data status (from $MANIFEST):"
    echo ""
    for name in $(_list_sources); do
        local desc
        desc=$(_parse_source "$name" "description")
        if [ -d "$DATA_DIR/$name" ]; then
            printf "  ✓ %-14s %s\n" "$name" "$desc"
        else
            printf "  ✗ %-14s %s (run: bash scripts/fetch-data.sh %s)\n" "$name" "$desc" "$name"
        fi
    done
    echo ""
}

# Fetch a single source by name.
_fetch_one() {
    local name="$1"
    local repo commit sha256 include_json

    repo=$(_parse_source "$name" "repo")
    commit=$(_parse_source "$name" "commit")
    sha256=$(_parse_source "$name" "archive_sha256")
    include_json=$(_parse_source "$name" "include")

    if [ -z "$repo" ] || [ -z "$commit" ]; then
        echo "ERROR: source '$name' not found in $MANIFEST" >&2
        return 1
    fi

    local url="https://github.com/${repo}/archive/${commit}.zip"
    local dest="$DATA_DIR/$name"
    local tmpdir
    tmpdir=$(mktemp -d)

    # Clean up temp dir on exit from this function
    trap "rm -rf '$tmpdir'" RETURN

    echo "Fetching $name from $url ..."
    curl -fsSL "$url" -o "$tmpdir/archive.zip"

    # Verify checksum (skip if PLACEHOLDER — first-time bootstrap)
    if [ "$sha256" != "PLACEHOLDER" ] && [ -n "$sha256" ]; then
        local actual
        actual=$(sha256sum "$tmpdir/archive.zip" | cut -d' ' -f1)
        if [ "$actual" != "$sha256" ]; then
            echo "ERROR: SHA-256 mismatch for $name!" >&2
            echo "  Expected: $sha256" >&2
            echo "  Actual:   $actual" >&2
            return 1
        fi
        echo "  Checksum OK"
    else
        echo "  Checksum: PLACEHOLDER (skipping verification)"
    fi

    # Extract to temp, stripping the GitHub prefix dir ({Repo}-{commit}/)
    unzip -q "$tmpdir/archive.zip" -d "$tmpdir/extracted"

    # GitHub archives have a single top-level dir: {RepoName}-{full-commit}/
    local prefix_dir
    prefix_dir=$(ls -d "$tmpdir/extracted"/*/ | head -1)

    if [ -z "$prefix_dir" ]; then
        echo "ERROR: unexpected archive structure for $name" >&2
        return 1
    fi

    # Apply include filter if specified
    if [ -n "$include_json" ] && [ "$include_json" != "" ]; then
        mkdir -p "$tmpdir/filtered"
        # Parse JSON array of include paths via Python
        uv run python -c "
import json, shutil, sys
from pathlib import Path

include = json.loads('$include_json')
src = Path('$prefix_dir')
dst = Path('$tmpdir/filtered')

for pattern in include:
    source = src / pattern.rstrip('/')
    if not source.exists():
        print(f'  Warning: include path not found: {pattern}', file=sys.stderr)
        continue
    target = dst / pattern.rstrip('/')
    if source.is_dir():
        shutil.copytree(source, target, dirs_exist_ok=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    print(f'  Included: {pattern}')
"
        # Use filtered content
        rm -rf "$dest"
        mv "$tmpdir/filtered" "$dest"
    else
        # No filter — use everything
        rm -rf "$dest"
        mv "$prefix_dir" "$dest"
    fi

    echo "  Installed to $dest"
}

# Print checksums for all sources (for populating sources.toml)
_print_checksums() {
    echo "Downloading archives and computing SHA-256 checksums..."
    echo ""
    for name in $(_list_sources); do
        local repo commit
        repo=$(_parse_source "$name" "repo")
        commit=$(_parse_source "$name" "commit")
        local url="https://github.com/${repo}/archive/${commit}.zip"
        local tmpfile
        tmpfile=$(mktemp)
        echo "  $name: $url"
        curl -fsSL "$url" -o "$tmpfile"
        local checksum
        checksum=$(sha256sum "$tmpfile" | cut -d' ' -f1)
        echo "  archive_sha256 = \"$checksum\""
        echo ""
        rm -f "$tmpfile"
    done
}

# --- Main ---

case "${1:-help}" in
    --status|status)
        _show_status
        ;;
    --checksums|checksums)
        _print_checksums
        ;;
    all)
        for name in $(_list_sources); do
            _fetch_one "$name"
            echo ""
        done
        echo "Done. All sources fetched."
        ;;
    help|--help|-h)
        echo "Usage: $0 {<source-name>|all|--status|--checksums}"
        echo ""
        echo "Commands:"
        echo "  <name>       Fetch a single source (e.g., wycheproof, acvp)"
        echo "  all          Fetch all sources from data/sources.toml"
        echo "  --status     Show which sources are present/missing"
        echo "  --checksums  Download all archives and print SHA-256 (for updating sources.toml)"
        echo ""
        echo "Sources are defined in data/sources.toml."
        ;;
    *)
        _fetch_one "$1"
        ;;
esac
```

- [ ] **Step 2: Make executable**

```bash
chmod +x scripts/fetch-data.sh
```

- [ ] **Step 3: Test `--status` (should show all missing)**

Run: `bash scripts/fetch-data.sh --status`
Expected: all 4 sources show as `✗` (missing)

- [ ] **Step 4: Test fetching a small source (cctv, ~3.8 MB)**

Run: `bash scripts/fetch-data.sh cctv`
Expected: downloads, prints "Checksum: PLACEHOLDER", extracts to `data/cctv/`

Verify: `ls data/cctv/ed25519/ed25519vectors.json`
Expected: file exists

- [ ] **Step 5: Test fetching wycheproof**

Run: `bash scripts/fetch-data.sh wycheproof`
Expected: downloads, extracts `testvectors_v1/` and `LICENSE` only

Verify: `ls data/wycheproof/testvectors_v1/aes_gcm_test.json`
Expected: file exists

Verify: `ls data/wycheproof/schemas/ 2>/dev/null`
Expected: not found (excluded by include filter)

- [ ] **Step 6: Compute real checksums and update manifest**

Run: `bash scripts/fetch-data.sh --checksums`
Expected: prints SHA-256 for each source's archive zip

Update `data/sources.toml` with the real `archive_sha256` values printed.

- [ ] **Step 7: Re-fetch cctv to test checksum verification**

```bash
rm -rf data/cctv
bash scripts/fetch-data.sh cctv
```

Expected: "Checksum OK" printed (not PLACEHOLDER)

- [ ] **Step 8: Test `--status` again**

Run: `bash scripts/fetch-data.sh --status`
Expected: cctv and wycheproof show `✓`, acvp and x509-limbo show `✗`

- [ ] **Step 9: Commit script and updated manifest**

```bash
git add scripts/fetch-data.sh data/sources.toml
git commit -m "feat(data): add manifest-driven fetch script with checksum verification"
```

---

### Task 6: Fetch all data and verify tests work

**Files:** None created or modified — this is a verification task.

- [ ] **Step 1: Fetch remaining sources**

```bash
bash scripts/fetch-data.sh acvp
bash scripts/fetch-data.sh x509-limbo
```

Note: ACVP is ~600 MB download, will take a few minutes.

- [ ] **Step 2: Update checksums for acvp and x509-limbo**

If they were still PLACEHOLDER, run `bash scripts/fetch-data.sh --checksums`,
update `data/sources.toml`, and commit:

```bash
git add data/sources.toml
git commit -m "chore(data): fill in real SHA-256 checksums for all sources"
```

- [ ] **Step 3: Verify data resolver finds the new locations**

Run:
```bash
uv run python -c "
from pkcs11_check.testcases.data import WYCHEPROOF_DIR, CCTV_DIR, ACVP_DIR, X509_LIMBO_DIR
print('wycheproof:', WYCHEPROOF_DIR, WYCHEPROOF_DIR.exists())
print('cctv:      ', CCTV_DIR, CCTV_DIR.exists())
print('acvp:      ', ACVP_DIR, ACVP_DIR.exists())
print('x509-limbo:', X509_LIMBO_DIR, X509_LIMBO_DIR.exists())
"
```

Expected: all 4 print `True`.

- [ ] **Step 4: Run a quick smoke test with wycheproof**

Run against SoftHSM2 (fastest):
```bash
bash local-builds/test.sh softhsm2 -m wycheproof -x --maxfail=3 -q
```

Expected: tests collect and run (pass/skip/xfail). If tests skip with
"Wycheproof vectors not available", the resolver is pointing to the wrong path.

- [ ] **Step 5: Run a quick smoke test with ACVP**

```bash
bash local-builds/test.sh softhsm2 -m acvp -x --maxfail=3 -q
```

Expected: ACVP tests collect and run.

- [ ] **Step 6: Run a quick smoke test with CCTV**

```bash
bash local-builds/test.sh softhsm2 -m cctv -x --maxfail=3 -q
```

Expected: CCTV tests collect and run.

- [ ] **Step 7: Run full non-vector test suite to confirm nothing broke**

```bash
bash local-builds/test.sh softhsm2 -m "not (wycheproof or acvp or cctv or stress or fuzz or slow)" -q
```

Expected: ~2300 tests pass (same as before the change).

---

### Task 7: Add data-missing warning to `docker/test.sh`

**Files:**
- Modify: `docker/test.sh`

- [ ] **Step 1: Add warning after variable setup, before compose invocation**

After line 31 (`service="test-$service"` block), add:

```bash
# Warn if test vector data is not present
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ ! -f "$PROJECT_ROOT/data/sources.toml" ]; then
    echo "Warning: data/sources.toml not found. Test vector data may be missing." >&2
    echo "  Run: bash scripts/fetch-data.sh all" >&2
    echo "" >&2
elif [ ! -d "$PROJECT_ROOT/data/wycheproof" ] && [ ! -d "$PROJECT_ROOT/data/acvp" ]; then
    echo "Warning: No test vector data found in data/. Vector tests will be skipped." >&2
    echo "  Run: bash scripts/fetch-data.sh all" >&2
    echo "" >&2
fi
```

- [ ] **Step 2: Commit**

```bash
git add docker/test.sh
git commit -m "feat(docker): warn when test vector data is missing"
```

---

### Task 8: Run linting, type check, and meta-tests

**Files:** None — verification only.

- [ ] **Step 1: Ruff lint**

Run: `uv run ruff check src/ tests/`
Expected: no errors

- [ ] **Step 2: Ruff format check**

Run: `uv run ruff format --check src/ tests/`
Expected: no changes needed

- [ ] **Step 3: Mypy**

Run: `uv run mypy src/`
Expected: passes

- [ ] **Step 4: Meta-tests**

Run: `uv run python -m pytest tests/ -q`
Expected: all meta-tests pass

---

### Task 9: Update CLAUDE.md references

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add data fetch to Quick Reference commands section**

After the "Test profiles" block in the Commands section, add:

```markdown
# Test vector data (third-party, fetched separately)
bash scripts/fetch-data.sh --status          # show what's present/missing
bash scripts/fetch-data.sh all               # fetch all sources (~800 MB)
bash scripts/fetch-data.sh wycheproof        # fetch individual source
```

- [ ] **Step 2: Update Docker test usage section**

Add to the "Docker test usage" bullet list:

```markdown
- Test vector data is bind-mounted read-only from host `data/` into containers — NOT copied into images
- Run `bash scripts/fetch-data.sh all` before Docker tests to populate data
```

- [ ] **Step 3: Add data directory to Architecture section**

After the "Two test directories" subsection, add:

```markdown
### Test vector data (`data/`)
- `data/sources.toml` — tracked manifest: pinned commits, SHA-256 checksums, include filters
- `data/.gitignore` — tracked, ignores extracted directories
- `data/wycheproof/`, `data/cctv/`, `data/acvp/`, `data/x509-limbo/` — gitignored, fetched by `scripts/fetch-data.sh`
- Own test data (mechanism_vectors, KAT JSONs) stays in `src/pkcs11_check/testcases/data/` (tracked)
- Override data location with `PKCS11_CHECK_DATA_DIR` env var
```

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md with new data directory structure"
```
