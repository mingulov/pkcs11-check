# fetch-data and fetch-disabled CLI Commands Design

**Date:** 2026-04-01
**Status:** Approved (v2 — gap analysis applied)

## Problem

Installed users (`pip install pkcs11-check`) cannot:
1. Download third-party test vectors (Wycheproof, ACVP, CCTV, x509-limbo) — `scripts/fetch-data.sh` is not in the wheel
2. Download the disabled-tests baseline — `config/disabled-tests.txt` is dev-only
3. Find vectors at runtime — `_find_project_root()` fails for installed packages

## Solution

Two new CLI commands, a fixed data path resolver, and auto-discovery of the disabled baseline.

## Data path resolution

New logic in `src/pkcs11_check/testcases/data/__init__.py`, replacing `_find_project_root()`:

1. `PKCS11_CHECK_DATA_DIR` env var set → use it
2. Repo root `data/` dir exists and has fetched content → use it (dev/repo mode)
3. Fallback → `~/.local/share/pkcs11-check/data/` (XDG standard, Linux-primary; macOS/Windows users can use `PKCS11_CHECK_DATA_DIR`)

The `_find_project_root()` function is kept only for step 2 detection. Step 3 is the new default for installed packages.

## `sources.toml` location

**Move** (not copy) `data/sources.toml` → `src/pkcs11_check/testcases/data/sources.toml`. This ships in the wheel. The `data/` directory at repo root remains as the gitignored destination for fetched vectors.

`scripts/fetch-data.sh` (the only consumer of the old location) is being deleted, so no duplication needed.

## `pkcs11-check fetch-data`

**File:** `src/pkcs11_check/cli/fetch_cmd.py`

**Usage:**
```
pkcs11-check fetch-data [name|all] [--status] [--checksums] [--data-dir PATH]
```

**Behavior:**
- Reads `sources.toml` from the installed package (`importlib.resources` or `Path(__file__).parent`)
- `--status`: shows present/missing status for each source with description
- `all`: downloads all sources
- `<name>` (e.g., `wycheproof`): downloads one source
- `--data-dir`: overrides target directory (default: resolved data dir)
- `--checksums`: downloads all archives and prints SHA-256 (dev utility for updating `sources.toml`)
- Existing data is **overwritten** — no `--force` flag needed

**Download pipeline per source:**
1. Download `https://github.com/{repo}/archive/{commit}.zip` via `urllib.request`
2. Download in chunks with `rich.progress.Progress` bar (ACVP is ~800MB)
3. Verify SHA-256 against `archive_sha256` from manifest
4. Extract zip (`zipfile` stdlib), strip GitHub prefix directory (`{RepoName}-{commit}/`)
5. Apply `include` filter (copy only matching paths to temp dir)
6. Atomically replace: `rm -rf` old dest, `mv` temp to final `{data_dir}/{name}/`
7. If interrupted before step 6, no partial data remains (temp dir cleaned up)

**Output:** Rich console with download progress bar, checksum verification, extraction count.

**No new dependencies:** `urllib.request`, `tomllib`, `hashlib`, `zipfile` — all stdlib.

## `pkcs11-check fetch-disabled`

**File:** Same `src/pkcs11_check/cli/fetch_cmd.py`

**Usage:**
```
pkcs11-check fetch-disabled [--data-dir PATH]
```

**Behavior:**
1. Downloads `https://raw.githubusercontent.com/mingulov/pkcs11-check/main/config/disabled-tests.txt`
2. Validates content (non-empty, lines look like pytest nodeids containing `::`)
3. Saves to `{data_dir}/disabled-tests.txt`
4. Prints count of disabled entries

## Disabled baseline auto-discovery

**File:** `src/pkcs11_check/core/test_selection.py` (modify `load_disabled_baseline`)

Resolution order:
1. `--disabled-tests-file` explicit CLI flag → use it
2. `--ignore-disabled-tests` flag → skip entirely
3. `disabled_tests_file` in TOML config → use it
4. `{resolved_data_dir}/disabled-tests.txt` exists → use it automatically
5. None of above → no baseline, all tests run

When auto-discovered, print: "Using disabled baseline: {path} ({N} entries). Use --ignore-disabled-tests to skip."

## Files changed

| File | Change |
|------|--------|
| `src/pkcs11_check/cli/fetch_cmd.py` | NEW — fetch-data and fetch-disabled commands |
| `src/pkcs11_check/cli/app.py` | Register new subcommands via `app.command()` |
| `src/pkcs11_check/testcases/data/__init__.py` | Fix path resolution with XDG fallback |
| `src/pkcs11_check/testcases/data/sources.toml` | MOVED from `data/sources.toml` |
| `src/pkcs11_check/core/test_selection.py` | Auto-discover disabled baseline from data dir |
| `src/pkcs11_check/config.py` | Expose resolved data dir for CLI commands |
| `data/sources.toml` | DELETE — moved into package |
| `scripts/fetch-data.sh` | DELETE — replaced by Python CLI |
| `docs/commands.md` | Replace `scripts/fetch-data.sh` references with new CLI commands |
| `docs/architecture.md` | Update test vector data section (fetched by `pkcs11-check fetch-data`) |
| `README.md` | Update quick start for installed workflow |

## Testing

Meta-tests (`tests/`) for the fetch commands:
- Test `sources.toml` parsing (read real manifest, verify structure)
- Test path resolution logic (env var, repo root detection, XDG fallback)
- Test disabled baseline auto-discovery logic
- Download tests are manual / integration-only (no mocking network in unit tests)

## End-user workflow after implementation

```bash
pip install pkcs11-check

# Check what data is available
pkcs11-check fetch-data --status

# Download test vectors (~800 MB)
pkcs11-check fetch-data all

# Download disabled baseline
pkcs11-check fetch-disabled

# Run full suite
pkcs11-check test --module /path/to/module.so --pin 1234
# → 75K tests, disabled baseline auto-applied
```
