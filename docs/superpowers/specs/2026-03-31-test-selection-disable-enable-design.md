# Test Selection: Disable/Enable System

**Date:** 2026-03-31
**Status:** Draft
**Scope:** Production-ready test deselection for CI/release workflows, supporting 50K+ disabled tests

## Problem

The test suite has 100K+ tests across 200+ files. Not all tests pass on all modules.
For CI/release workflows, we need a way to **disable** specific tests so they are
completely excluded from execution and reporting (not skipped, not counted).
Later, developers need an **enable mode** to re-run disabled tests for debugging.

Requirements:
- Support 50K+ disabled test entries efficiently
- Disabled tests must NOT appear in results (not "skipped", invisible)
- Works in all isolation modes (auto/file/test/none)
- Config-file driven (TOML + external text file for bulk entries)
- CLI flag for enable (debug) mode
- Pattern-based disable: exact nodeids, file globs, markers

## Design

### Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│  Main Process (test_cmd.py / file_runner.py)            │
│                                                         │
│  1. Load TestSelectionConfig from TOML                  │
│  2. Build disabled-nodeid hash set from external file   │
│  3. Expand patterns → additional disabled nodeids       │
│  4. Filter file-level: skip files with 0 enabled tests  │
│  5. For mixed files: write per-file deselect list       │
│     → set PKCS11_CHECK_DESELECT_FILE env var            │
│  6. Spawn subprocess for remaining files                │
│                                                         │
│  Enable mode (--test-selection-mode=debug):             │
│  → Invert: ONLY run tests matching disabled criteria    │
└────────────────────┬────────────────────────────────────┘
                     │ PKCS11_CHECK_DESELECT_FILE=<path>
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Subprocess (plugin.py:pytest_collection_modifyitems)   │
│                                                         │
│  7. Read deselect file → hash set                       │
│  8. Remove matching items from collection               │
│  9. Call config.hook.pytest_deselected(items=...)       │
│     → Deselected tests invisible in results             │
└─────────────────────────────────────────────────────────┘
```

### Data Flow

```
pkcs11_check.toml                    config/disabled-tests.txt
       │                                      │
       │  [test-selection]                    │  (50K+ lines, one nodeid per line)
       │  disabled-nodeids-file = "..."       │
       │  disabled-patterns = [...]           │
       │  disabled-markers = [...]            │
       └──────────┬───────────────────────────┘
                  ▼
        TestSelectionConfig (pydantic model)
                  │
                  ▼
     ┌─ Main Process: build DisabledTestIndex ─┐
     │                                          │
     │  1. Load external file → set[str]        │
     │  2. Compile glob patterns                │
     │  3. Collect marker names                 │
     │  4. O(1) lookup by nodeid                │
     │  5. Pattern match by file path           │
     └──────────────┬───────────────────────────┘
                    │
        ┌───────────┴──────────────┐
        ▼                          ▼
  File-level filter         Per-file deselect
  (skip entire file         (write subset to
   if all disabled)          temp file for
                             subprocess)
```

### Configuration

#### TOML Configuration (`pkcs11_check.toml`)

```toml
[test-selection]
# External file with one nodeid per line (50K+ entries).
# Paths relative to TOML file location, or absolute.
disabled-nodeids-file = "config/disabled-tests.txt"

# File glob patterns. Any test whose file path matches is disabled.
disabled-patterns = [
    "**/wycheproof/**",
    "**/stress/**",
    "**/fuzz/**",
]

# Pytest marker names. Any test carrying one of these markers is disabled.
disabled-markers = ["slow", "fuzz", "stress"]
```

#### External Disabled Tests File (`config/disabled-tests.txt`)

One pytest nodeid per line. Comments allowed with `#`. Blank lines ignored.

```
# AES-256-GCM tests failing on SoftHSM2
src/pkcs11_check/testcases/test_encrypt.py::TestAESGCM::test_256_roundtrip
src/pkcs11_check/testcases/test_encrypt.py::TestAESGCM::test_256_multipart

# Parametrized test entries
src/pkcs11_check/testcases/test_sign.py::TestRSA::test_sign_verify[rsa-2048-pkcs1-sha256]
src/pkcs11_check/testcases/test_sign.py::TestRSA::test_sign_verify[rsa-3072-pkcs1-sha256]
```

#### CLI Flags

```bash
# Normal mode: disabled tests are excluded
uv run pkcs11-check test -m /path/to/module.so

# Debug mode: run ONLY tests matching disabled criteria
uv run pkcs11-check test -m /path/to/module.so --test-selection-mode=debug
```

### Core Components

#### 1. `TestSelectionConfig` (config.py extension)

New pydantic model for the `[test-selection]` TOML section.

```python
class TestSelectionConfig(BaseModel):
    disabled_nodeids_file: Path | None = None
    disabled_patterns: list[str] = Field(default_factory=list)
    disabled_markers: list[str] = Field(default_factory=list)
```

Loaded from `pkcs11_check.toml` `[test-selection]` section.
No environment variable support — this is config-file-only by design (50K+ entries
don't belong in env vars).

#### 2. `DisabledTestIndex` (new module: `core/test_selection.py`)

Pre-computed index for O(1) lookups. Built once at startup, used by both
main process (file filtering) and subprocess (item deselection).

```python
class DisabledTestIndex:
    """Pre-computed index for fast test selection lookups."""

    nodeids: set[str]           # Exact nodeid matches (O(1))
    file_patterns: list[Pattern]  # Compiled glob patterns for file paths
    markers: set[str]             # Marker names to disable

    def is_disabled(self, nodeid: str, file_path: str, item_markers: set[str]) -> bool
    def disabled_nodeids_for_file(self, file_path: str, items: list[CollectedPytestItem]) -> set[str]
    def all_disabled_for_file(self, file_path: str, items: list[CollectedPytestItem]) -> bool
```

**Memory:** ~5-10 MB for 50K nodeids in a Python `set[str]`. Acceptable.

#### 3. Main Process Integration (file_runner.py)

In `discover_auto_isolation_units()` and `run_isolated_pytest_units()`:

```
Before current logic:
  1. Build DisabledTestIndex from config
  2. For each file unit:
     a. Collect items for file (already done by collect_pytest_item_metadata)
     b. Check: all items disabled? → skip file entirely (no subprocess)
     c. Some items disabled? → write deselect file, pass via env var
     d. No items disabled? → run normally
```

**Per-file deselect file optimization:**
When a file has 500 tests and 200 are disabled, we write only the 200 disabled
nodeids for that file to a temp file, set `PKCS11_CHECK_DESELECT_FILE`, and spawn.
This avoids passing 50K entries to every subprocess.

#### 4. Subprocess Integration (plugin.py)

**No changes needed to the existing deselect mechanism.**

The existing `pytest_collection_modifyitems()` already:
1. Reads `PKCS11_CHECK_DESELECT_FILE` env var
2. Loads nodeids into a `set[str]`
3. Removes matching items via `config.hook.pytest_deselected()`
4. Deselected items do NOT appear in results (not skipped, not counted)

This is exactly the behavior we want. The main process just needs to set the
env var pointing to the correct deselect file for each subprocess.

### Enable (Debug) Mode

CLI flag `--test-selection-mode=debug` inverts the selection:

```
Normal mode:  Run ALL tests MINUS disabled ones
Debug mode:   Run ONLY tests matching disabled criteria
```

**Implementation:**
1. Load `DisabledTestIndex` as usual
2. Instead of writing disabled nodeids to deselect file, write ALL OTHER nodeids
3. Subprocess deselects everything except the disabled tests
4. Result: only previously-disabled tests run

**Alternative (simpler):**
For debug mode, generate a pytest `-k` expression or `--deselect` list that
inverts the selection. But `-k` doesn't scale to 50K entries.

**Chosen approach:** Write the complement set to the deselect file.
For a file with 800 tests where 200 are disabled, debug mode writes the
600 non-disabled nodeids to the deselect file, leaving only the 200 to run.

### Isolation Mode Interactions

| Isolation Mode | Test Selection Behavior |
|---|---|
| `none` | Plugin `pytest_collection_modifyitems()` handles deselect in-process. Main process writes deselect file before `pytest.main()`. |
| `file` | Main process filters: skip files where ALL tests disabled. For mixed files, set `PKCS11_CHECK_DESELECT_FILE` in subprocess env. |
| `test` | Main process filters individual test nodeids. Skip spawning for disabled tests entirely. |
| `auto` | Combined: file-level skip for all-disabled, per-test skip in test-level units, deselect file for mixed file-level units. |

### Performance Characteristics

| Operation | Complexity | Notes |
|---|---|---|
| Load 50K nodeids from file | O(n) one-time | ~50ms, done once at startup |
| Hash set lookup per test | O(1) | Python `set.__contains__` |
| File pattern match per test | O(p) | p = number of patterns (typically <10) |
| Marker check per test | O(1) | `set` intersection |
| Total overhead for 100K tests | ~200ms | Negligible vs. test execution time |
| Memory for 50K nodeids | ~8 MB | Python `set[str]` overhead |

### File Format: Disabled Tests File

```text
# Lines starting with # are comments
# Blank lines are ignored
# One pytest nodeid per line
# Nodeids must match pytest's internal representation exactly

src/pkcs11_check/testcases/test_encrypt.py::TestAES::test_roundtrip[aes-256-gcm]
src/pkcs11_check/testcases/test_sign.py::TestRSA::test_sign_verify[rsa-2048-pkcs1-sha256]
```

**Validation:** On load, warn (not error) if a nodeid doesn't match any known
test file path. This handles stale entries after test refactors without breaking CI.

### Interaction with Existing Mechanisms

| Mechanism | Relationship |
|---|---|
| `PKCS11_CHECK_DESELECT_FILE` (crash recovery) | Test selection uses the SAME env var/mechanism. Crash recovery and test selection deselect files are merged if both are active. |
| `-k` / `-m` pytest filters | Applied BEFORE test selection. Test selection operates on the already-filtered set. |
| `--p11-skip-unsupported` | Applied AFTER test selection. Skipped tests appear as "skipped"; deselected tests are invisible. |
| `@pytest.mark.skip` / `@pytest.mark.xfail` | Independent. These modify test behavior; deselection removes tests entirely. |
| Adaptive isolation policy (`promoted_files`, `crashed_tests`) | Independent. Test selection filters before isolation planning. |

### Merging with Crash Recovery Deselect

When both test selection and crash recovery produce deselect files for the same
subprocess, the main process merges them (union of both nodeid sets) into a single
file before setting `PKCS11_CHECK_DESELECT_FILE`. This avoids conflicts between
the two mechanisms.

```
test_selection_deselect = {"test_a", "test_b", "test_c"}
crash_recovery_deselect = {"test_x"}  # identified as crash culprit
merged_deselect = test_selection_deselect | crash_recovery_deselect
# → write to single temp file → set PKCS11_CHECK_DESELECT_FILE
```

### New Files

| File | Purpose |
|---|---|
| `src/pkcs11_check/core/test_selection.py` | `TestSelectionConfig`, `DisabledTestIndex`, loading logic |
| `config/disabled-tests.txt` | External disabled tests list (gitignored or tracked per module) |

### Modified Files

| File | Changes |
|---|---|
| `config.py` | Add `test_selection` field to `P11TestConfig` or load separately |
| `cli/test_cmd.py` | Add `--test-selection-mode` CLI flag; load `DisabledTestIndex`; pass to file runner |
| `core/file_runner.py` | `discover_auto_isolation_units()` / `run_isolated_pytest_units()`: filter units using index, write per-file deselect files |
| `plugin.py` | No changes needed (existing deselect mechanism reused as-is) |

### Future Considerations

- **Per-module disable lists:** Different modules may need different disabled sets.
  The config can support `disabled-nodeids-file = "config/disabled-softhsm2.txt"`
  selected by environment or module path.
- **Disable reason tracking:** Add optional inline comments or a separate reasons file.
- **Auto-generate disable list from results:** Script to produce disabled-tests.txt
  from a failing results.json.
- **Statistics:** Report count of disabled tests separately (not in pass/fail/skip counts).
