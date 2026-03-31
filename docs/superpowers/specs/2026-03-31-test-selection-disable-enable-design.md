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
│  2. Build DisabledTestIndex (hash set + patterns)       │
│  3. Run collection subprocess to get per-item metadata  │
│  4. For each file unit, classify items:                 │
│     - all disabled → skip file (no subprocess spawned)  │
│     - some disabled → write per-file deselect file      │
│     - none disabled → run normally                      │
│  5. Pass PKCS11_CHECK_DESELECT_FILE per subprocess      │
│                                                         │
│  Enable mode (--test-selection-mode=debug):             │
│  → Invert: skip files with NO disabled tests, deselect  │
│    all but the disabled tests in remaining files        │
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

### Configuration

#### TOML Configuration (`pkcs11_check.toml`)

Separate TOML section. Loaded by a dedicated `TestSelectionConfig` model
(independent from `P11TestConfig` to keep config concerns separated).

```toml
[test-selection]
# External file with one nodeid per line (50K+ entries).
# Path relative to TOML file location.
disabled-nodeids-file = "config/disabled-tests.txt"

# File glob patterns. Matched against the nodeid's file part.
# Any test whose file path matches is disabled.
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
Nodeids must use **paths relative to the CWD** (matching pytest's internal
representation — the same format pytest shows in `-v` output and JSONL records).

```
# AES-256-GCM tests failing on SoftHSM2
src/pkcs11_check/testcases/test_encrypt.py::TestAESGCM::test_256_roundtrip
src/pkcs11_check/testcases/test_encrypt.py::TestAESGCM::test_256_multipart

# Parametrized test entries (exact variant)
src/pkcs11_check/testcases/test_sign.py::TestRSA::test_sign_verify[rsa-2048-pkcs1-sha256]
src/pkcs11_check/testcases/test_sign.py::TestRSA::test_sign_verify[rsa-3072-pkcs1-sha256]
```

**Path normalization:** On load, the file part of each nodeid is resolved to
`Path(file_part).resolve()`. At lookup time, `Path(item.path).resolve()` is used.
This ensures matching regardless of CWD differences between load time and run time.

#### CLI Flags

```bash
# Normal mode: disabled tests are excluded
uv run pkcs11-check test -m /path/to/module.so

# Debug mode: run ONLY tests matching disabled criteria
uv run pkcs11-check test -m /path/to/module.so --test-selection-mode=debug
```

### Core Components

#### 1. `TestSelectionConfig` (separate model in `core/test_selection.py`)

Independent from `P11TestConfig`. Loaded directly from `pkcs11_check.toml`
`[test-selection]` section using pydantic's TOML source. This avoids coupling
the existing flat config model with nested test-selection concerns.

```python
class TestSelectionConfig(BaseModel):
    disabled_nodeids_file: Path | None = None
    disabled_patterns: list[str] = Field(default_factory=list)
    disabled_markers: list[str] = Field(default_factory=list)

    @classmethod
    def from_toml(cls, path: Path) -> TestSelectionConfig: ...
```

#### 2. `DisabledTestIndex` (in `core/test_selection.py`)

Pre-computed index for O(1) lookups. Built once at startup after collection
metadata is available (needed for marker-based decisions).

```python
class DisabledTestIndex:
    """Pre-computed index for fast test selection lookups."""

    _nodeids: set[str]              # Exact nodeid matches (O(1)), path-resolved
    _resolved_file_set: set[str]    # Resolved file paths from disabled nodeids
    _file_patterns: list[tuple[Pattern, str]]  # (compiled glob, original pattern)
    _markers: set[str]              # Marker names to disable

    def is_disabled(self, nodeid: str, resolved_file: str, item_markers: frozenset[str]) -> bool:
        """Check if a single test item should be disabled.

        Matching rules (any match = disabled):
        1. Exact nodeid in _nodeids (O(1) hash lookup)
        2. File path matches any compiled glob in _file_patterns
        3. item_markers intersects _markers
        """

    def disabled_nodeids_for_file(
        self, items: list[CollectedPytestItem]
    ) -> set[str]:
        """Return the set of disabled nodeids among the given items."""

    def all_disabled_nodeids(self) -> set[str]:
        """Return ALL exact nodeids from the external file. Used for
        isolation=none deselection. Does NOT include pattern/marker matches
        (those are handled separately by the plugin)."""

    def all_disabled_for_file(
        self, items: list[CollectedPytestItem]
    ) -> bool:
        """True if every item in the file is disabled by this index."""

    def no_disabled_for_file(
        self, items: list[CollectedPytestItem]
    ) -> bool:
        """True if no item in the file is disabled. Used for debug mode."""

    def fingerprint(self) -> str:
        """Stable hash of config for resume state fingerprinting.
        Based on file path + mtime, patterns, markers."""
```

**Matching semantics for parametrized tests:**
- Exact nodeid match: matches only the specific parametrized variant
  (`test_foo[aes-256]` disables only that variant, not `test_foo[aes-128]`)
- File pattern match: disables ALL variants in matching files
- Marker match: disables ALL variants of tests carrying the marker

**Memory:** ~5-10 MB for 50K nodeids in a Python `set[str]`. Acceptable.

#### 3. Main Process Integration (file_runner.py)

The `DisabledTestIndex` is passed as a parameter through the call chain:
`test_cmd.py` → `discover_auto_isolation_units()` → `run_isolated_pytest_units()`.

**In `discover_auto_isolation_units()` — unit list filtering:**

```
After collection metadata is gathered (existing step):
  1. For each file unit with collected items:
     a. Compute disabled set via index.disabled_nodeids_for_file(items)
     b. all_disabled_for_file() → skip file entirely (remove from unit list)
     c. Some disabled → store disabled set for this file in a dict
        (keyed by normalized file path)
     d. None disabled → no action
  2. Return filtered unit list + disabled-per-file dict
```

**In `run_isolated_pytest_units()` — per-subprocess deselect files:**

```
For each unit in the run loop:
  1. Look up the file's disabled set from the dict
  2. Write disabled nodeids to a temp file
  3. Set PKCS11_CHECK_DESELECT_FILE in the subprocess env
  4. Spawn subprocess as normal
```

**Crash recovery merging:**
The test selection disabled set for a file is computed once and stored.
When the iterative deselect loop runs (lines 2091-2311), it unions the
crash-recovery deselect set with the test selection disabled set before
writing the combined deselect file:

```python
# Inside _escalate_current_file() / iterative deselect:
test_selection_disabled = selection_disabled_by_file.get(file_key, set())
combined = test_selection_disabled | crash_culprits
deselect_path.write_text("\n".join(sorted(combined)) + "\n")
```

#### 4. Collection Metadata Bypass

The `collect_pytest_item_metadata()` subprocess (used by `discover_auto_isolation_units()`)
must NOT apply test selection deselection. It needs to see ALL items to correctly
determine which files have disabled tests.

**Implementation:** The collection subprocess unsets `PKCS11_CHECK_DESELECT_FILE`
in its environment. Since `test_cmd.py` controls the env passed to collection,
this is natural — test selection deselect files are only written AFTER collection
returns and the `DisabledTestIndex` is built.

#### 5. `isolation=none` Mode

When `isolation=none`, `test_cmd.py` calls `pytest.main()` directly (no file_runner
involvement). Two mechanisms work together without overlap:

**Division of responsibility:**
- `PKCS11_CHECK_DESELECT_FILE` → exact nodeid matches only (from external file)
- `PKCS11_CHECK_SELECTION_CONFIG` → pattern and marker matches (from TOML config)

The deselect file contains ONLY the exact nodeids from the external file. Pattern
and marker deselection is handled by the plugin via the config path env var.
This avoids double-deselection.

```python
# In test_cmd.py, isolation=="none" branch:
if selection_index is not None:
    exact_nodeids = selection_index.all_disabled_nodeids()
    if exact_nodeids:
        deselect_fd, deselect_raw = tempfile.mkstemp(...)
        os.close(deselect_fd)
        Path(deselect_raw).write_text("\n".join(sorted(exact_nodeids)) + "\n")
        os.environ["PKCS11_CHECK_DESELECT_FILE"] = deselect_raw
    # Signal config for pattern/marker deselection in plugin
    os.environ["PKCS11_CHECK_SELECTION_CONFIG"] = str(toml_path)
    # Signal debug mode if active
    if debug_mode:
        os.environ["PKCS11_CHECK_SELECTION_DEBUG"] = "1"
try:
    exit_code = pytest.main(args)
finally:
    # cleanup deselect file + env vars
```

#### 6. Plugin Integration (plugin.py)

For `isolation=none` mode, the plugin needs access to the `DisabledTestIndex` to
apply pattern and marker-based deselection (which can't be expressed as a flat
nodeid file). Three env vars coordinate this:

- `PKCS11_CHECK_DESELECT_FILE` — exact nodeid deselect file (existing)
- `PKCS11_CHECK_SELECTION_CONFIG` — path to TOML for pattern/marker matching
- `PKCS11_CHECK_SELECTION_DEBUG` — set to `"1"` for enable (debug) mode

```python
# In plugin.py pytest_collection_modifyitems():

# Existing: file-based deselect (exact nodeids only)
deselect_file = os.environ.get("PKCS11_CHECK_DESELECT_FILE")
if deselect_file:
    # ... existing logic (unchanged) ...

# New: pattern and marker deselection (for isolation=none)
selection_config_path = os.environ.get("PKCS11_CHECK_SELECTION_CONFIG")
if selection_config_path:
    config = TestSelectionConfig.from_toml(Path(selection_config_path))
    index = DisabledTestIndex.from_config(config)
    debug_mode = os.environ.get("PKCS11_CHECK_SELECTION_DEBUG") == "1"
    deselected = []
    remaining = []
    for item in items:
        item_markers = frozenset(m.name for m in item.iter_markers())
        disabled = index.is_disabled(
            item.nodeid, str(Path(item.path).resolve()), item_markers
        )
        # In debug mode, invert: deselect NON-disabled tests
        should_deselect = (not disabled) if debug_mode else disabled
        if should_deselect:
            deselected.append(item)
        else:
            remaining.append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = remaining
```

For isolated modes (auto/file/test), pattern and marker deselection is handled
in the main process during unit list filtering. The subprocess receives only the
flat nodeid deselect file (which already includes pattern/marker matches computed
by the main process). The plugin's `PKCS11_CHECK_SELECTION_CONFIG` path is NOT
set for isolated subprocesses — only the deselect file is used.

#### 7. Resume State Fingerprint

The `build_state_fingerprint()` function in `file_runner.py` must include the
test selection configuration in its fingerprint hash. This ensures that changing
`disabled-tests.txt` invalidates resume state:

```python
# In build_state_fingerprint(), add to hash input:
if selection_index is not None:
    hasher.update(b"selection:")
    hasher.update(selection_index.fingerprint().encode())
```

`DisabledTestIndex.fingerprint()` returns a stable hash of its configuration
(nodeids file path + mtime, patterns, markers) — not the full 50K entries.

### Enable (Debug) Mode

CLI flag `--test-selection-mode=debug` inverts the selection:

```
Normal mode:  Run ALL tests MINUS disabled ones
Debug mode:   Run ONLY tests matching disabled criteria
```

**Implementation:**
1. Load `DisabledTestIndex` as usual
2. File-level filtering inverts:
   - Files with NO disabled tests → skip entirely
   - Files with some/all disabled tests → include
3. Per-file deselect inverts: write the NON-disabled nodeids to the deselect file
   instead of the disabled ones. For a file with 800 tests where 200 are disabled,
   debug mode writes the 600 non-disabled nodeids, leaving only 200 to run.
4. For `isolation=none`, the plugin's pattern/marker check inverts similarly.

### Isolation Mode Interactions

| Isolation Mode | Test Selection Behavior |
|---|---|
| `none` | Plugin handles all deselection in-process via `PKCS11_CHECK_DESELECT_FILE` (exact nodeids) + `PKCS11_CHECK_SELECTION_CONFIG` (patterns/markers). |
| `file` | Main process: skip files where ALL tests disabled. Mixed files: write per-file deselect nodeids to temp file, set env var. |
| `test` | Main process: skip spawning for disabled test nodeids entirely. Only non-disabled nodeids become units. |
| `auto` | Combined: file-level skip for all-disabled files, per-test skip for test-level units, deselect file for mixed file-level units. |

### Performance Characteristics

| Operation | Complexity | Notes |
|---|---|---|
| Load 50K nodeids from file | O(n) one-time | ~50ms, done once at startup |
| Hash set lookup per test | O(1) | Python `set.__contains__` |
| File pattern match per test | O(p) | p = number of patterns (typically <10) |
| Marker check per test | O(1) | `set` intersection |
| Total overhead for 100K tests | ~200ms | Negligible vs. test execution time |
| Memory for 50K nodeids | ~8 MB | Python `set[str]` overhead |

### Validation of Disabled Tests File

On load, validate nodeids against known file paths. Report a summary, not
individual warnings:

```
⚠ Test selection: 234 stale entries (file not found), first 5:
  src/pkcs11_check/testcases/test_old.py::TestFoo::test_bar
  ...
Total loaded: 49766 / 50000 valid entries
```

Threshold: warn if > 10% are stale. Never error — stale entries are harmless
(nothing matches them).

### Interaction with Existing Mechanisms

| Mechanism | Relationship |
|---|---|
| `PKCS11_CHECK_DESELECT_FILE` (crash recovery) | Test selection uses the SAME env var/mechanism. Sets are merged (union) when both are active. |
| `-k` / `-m` pytest filters | Applied by pytest BEFORE `pytest_collection_modifyitems`. Test selection operates on the already-filtered set. |
| `--p11-skip-unsupported` | Applied AFTER deselection in `pytest_runtest_setup`. Skipped tests appear as "skipped"; deselected tests are invisible. |
| `@pytest.mark.skip` / `@pytest.mark.xfail` | Independent. These modify test behavior; deselection removes tests entirely. |
| Adaptive isolation policy | Test selection filters before isolation planning. Promoted files still get per-test granularity. |
| Resume state | Test selection config included in state fingerprint. Changing disabled list invalidates resume. |

### Merging with Crash Recovery Deselect

Both mechanisms write to the same `PKCS11_CHECK_DESELECT_FILE`. The merge happens
in the main process before spawning the retry subprocess:

```
test_selection_deselect = {"test_a", "test_b", "test_c"}  # from DisabledTestIndex
crash_recovery_deselect = {"test_x"}                       # identified crash culprit
merged_deselect = test_selection_deselect | crash_recovery_deselect
# → write to single temp file → set PKCS11_CHECK_DESELECT_FILE
```

### New Files

| File | Purpose |
|---|---|
| `src/pkcs11_check/core/test_selection.py` | `TestSelectionConfig`, `DisabledTestIndex`, loading/matching logic |
| `config/disabled-tests.txt` | Example external disabled tests list (gitignored, per-module) |

### Modified Files

| File | Changes |
|---|---|
| `cli/test_cmd.py` | Add `--test-selection-mode` CLI flag; load `DisabledTestIndex`; pass to file runner; write deselect file for `isolation=none` |
| `core/file_runner.py` | `discover_auto_isolation_units()`: accept `DisabledTestIndex`, filter unit list, return disabled-per-file dict. `run_isolated_pytest_units()`: accept disabled-per-file dict, merge with crash recovery deselect, write per-subprocess deselect files. `build_state_fingerprint()`: include selection config hash. |
| `plugin.py` | Add `PKCS11_CHECK_SELECTION_CONFIG` handling in `pytest_collection_modifyitems()` for pattern/marker deselection in `isolation=none` mode. |

### Future Considerations

- **Per-module disable lists:** Different modules may need different disabled sets.
  The config can support `disabled-nodeids-file = "config/disabled-softhsm2.txt"`
  selected by environment or module path.
- **Disable reason tracking:** Add optional inline comments or a separate reasons file.
- **Auto-generate disable list from results:** Script to produce disabled-tests.txt
  from a failing results.json.
- **Statistics:** Report count of disabled tests separately (not in pass/fail/skip counts).
