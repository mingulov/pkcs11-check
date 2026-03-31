# Production Disabled Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a phase-1 production disabled-baseline system that deselects one committed global list of exact pytest nodeids by default, with an explicit CLI opt-out.

**Architecture:** Keep the feature small. One new shared module owns baseline loading, normalization, fingerprinting, temp-file materialization, and pure unit-planning logic. `test_cmd.py` resolves whether the baseline is active, `plugin.py` performs exact deselection, and `file_runner.py` enforces the same baseline during isolated scheduling, resume, retries, and auto-escalation.

**Tech Stack:** Python 3.11+, typer, pytest, pydantic-settings, rich, uv

**Spec:** `docs/superpowers/specs/2026-03-31-production-disabled-baseline-design.md`

---

## Scope Locks

- One committed global baseline only.
- Runtime matching is exact nodeid only.
- Disabled tests are `deselected`, never `skipped`.
- Existing `skip` and `xfail` meanings stay intact.
- Default run honors repo config.
- `--ignore-disabled-tests` disables the baseline for one invocation.
- Offline helper proposes candidates only. It does not edit the committed baseline automatically.

## Files

**Create**
- `config/disabled-tests.txt`
- `pkcs11_check.toml`
- `src/pkcs11_check/core/test_selection.py`
- `scripts/generate-disabled-tests.py`
- `tests/test_test_selection.py`

**Modify**
- `src/pkcs11_check/config.py`
- `src/pkcs11_check/cli/test_cmd.py`
- `src/pkcs11_check/plugin.py`
- `src/pkcs11_check/core/file_runner.py`
- `tests/test_config.py`
- `tests/test_cli.py`
- `tests/test_plugin.py`
- `tests/test_file_runner.py`

## Task 1: Repo Default + Shared Loader

**Why**

Everything else depends on one canonical baseline representation.

**Files**
- Create: `config/disabled-tests.txt`
- Create: `pkcs11_check.toml`
- Create: `src/pkcs11_check/core/test_selection.py`
- Create: `tests/test_test_selection.py`
- Modify: `src/pkcs11_check/config.py`
- Modify: `tests/test_config.py`

- [ ] **Step 1: Write failing loader tests**

Add tests in `tests/test_test_selection.py` for:
- comment lines ignored
- blank lines ignored
- duplicates deduplicated
- exact parametrized nodeids preserved
- missing configured file raises `FileNotFoundError`
- fingerprint changes when file content changes

Use sample content like:

```python
text = """
# comment
src/pkcs11_check/testcases/test_encrypt.py::test_roundtrip

src/pkcs11_check/testcases/test_encrypt.py::test_roundtrip
src/pkcs11_check/testcases/acvp/aes/test_cfb.py::test_acvp_aes_cfb[AES-enc-tc1021]
""".strip()
```

- [ ] **Step 2: Write failing config tests**

In `tests/test_config.py`, add coverage for:
- repo `pkcs11_check.toml` enabling `disabled_tests_file`
- env override through `P11TEST_DISABLED_TESTS_FILE`
- config omission producing `None`

- [ ] **Step 3: Add repo config and committed empty baseline**

Create `pkcs11_check.toml`:

```toml
disabled_tests_file = "config/disabled-tests.txt"
```

Create `config/disabled-tests.txt`:

```text
# Global production disabled baseline.
# One exact pytest nodeid per line.
```

- [ ] **Step 4: Extend `P11TestConfig`**

Add this field in `src/pkcs11_check/config.py`:

```python
disabled_tests_file: Path | None = None
```

Keep the Python default `None`. The repo TOML is what turns the baseline on by default.

- [ ] **Step 5: Implement the shared loader**

Add `src/pkcs11_check/core/test_selection.py` with small focused primitives:

```python
@dataclass(frozen=True)
class DisabledBaseline:
    source_path: Path
    disabled_nodeids: frozenset[str]
    fingerprint: str


def parse_disabled_nodeids(text: str) -> list[str]:
    ...


def load_disabled_baseline(path: Path | None) -> DisabledBaseline | None:
    ...


def write_deselect_file(nodeids: Iterable[str]) -> Path:
    ...
```

Rules:
- `None` path means baseline disabled
- ignore blank and `#` lines
- fingerprint should include file content digest
- temp file output should be stable-sorted

- [ ] **Step 6: Verify**

Run:

```bash
uv run python -m pytest tests/test_test_selection.py tests/test_config.py -q
```

Expected: all new loader/config tests pass.

- [ ] **Step 7: Commit**

```bash
git add config/disabled-tests.txt pkcs11_check.toml src/pkcs11_check/core/test_selection.py src/pkcs11_check/config.py tests/test_test_selection.py tests/test_config.py
git commit -m "feat(selection): add production baseline loader and config"
```

## Task 2: Non-Isolated Default-On Behavior

**Why**

`--isolation none` is the simplest user-visible path and establishes the default-on contract.

**Files**
- Modify: `src/pkcs11_check/cli/test_cmd.py`
- Modify: `tests/test_cli.py`

- [ ] **Step 1: Write failing CLI tests**

Add tests in `tests/test_cli.py` for:
- default non-isolated run loads the configured baseline
- `--ignore-disabled-tests` suppresses loading
- missing configured baseline exits with code `2`
- JSON output mode still cleans up both `PKCS11_CHECK_REPORT_LOG` and `PKCS11_CHECK_DESELECT_FILE`

- [ ] **Step 2: Add the opt-out flag**

In `src/pkcs11_check/cli/test_cmd.py`, add:

```python
ignore_disabled_tests: bool = typer.Option(
    False,
    "--ignore-disabled-tests",
    help="Do not load the configured disabled baseline for this run",
)
```

- [ ] **Step 3: Resolve baseline activation once in `test_command()`**

Use the settings model or a tiny resolver helper so TOML/env/CLI all share one path:

```python
runtime_config = P11TestConfig(
    module=module,
    interface=interface,
    slot=slot,
    destructive=destructive,
    pin=pin,
)
baseline = None if ignore_disabled_tests else load_disabled_baseline(
    runtime_config.disabled_tests_file
)
```

- [ ] **Step 4: Apply baseline to `pytest.main()`**

Before the non-isolated `pytest.main(args)` call:
- materialize a cleaned temp deselect file when baseline is active
- set `PKCS11_CHECK_DESELECT_FILE`
- clean up temp file and env var in `finally`

- [ ] **Step 5: Verify**

Run:

```bash
uv run python -m pytest tests/test_cli.py -k "disabled or ignore_disabled" -q
```

Expected: new default-on and opt-out tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/cli/test_cmd.py tests/test_cli.py
git commit -m "feat(cli): honor disabled baseline by default in non-isolated runs"
```

## Task 3: Pure Selection Planning

**Why**

The isolated runner work is safer if the scheduling logic is tested as pure data transformation first.

**Files**
- Modify: `src/pkcs11_check/core/test_selection.py`
- Modify: `tests/test_test_selection.py`

- [ ] **Step 1: Write failing planning tests**

Add pure tests for:
- disabled test units removed from `units`
- fully-disabled file units removed
- mixed file units retained with `deselect_by_file`
- explicit nodeid targets in file mode treated like test units
- resume reconstruction from saved `units` produces the same plan

- [ ] **Step 2: Add `DisabledSelectionPlan`**

In `src/pkcs11_check/core/test_selection.py`, add:

```python
@dataclass(frozen=True)
class DisabledSelectionPlan:
    units: list[str]
    deselect_by_file: dict[str, set[str]]
    baseline_fingerprint: str


def build_disabled_selection_plan(
    *,
    units: list[str],
    disabled_nodeids: set[str],
    baseline_fingerprint: str,
    collected_items: list[CollectedPytestItem] | None,
) -> DisabledSelectionPlan:
    ...
```

Rules:
- disabled nodeid units are dropped
- fully-disabled file units are dropped
- mixed file units get exact nodeids in `deselect_by_file`
- if metadata is unavailable, never invent a per-file deselect set

- [ ] **Step 3: Verify**

Run:

```bash
uv run python -m pytest tests/test_test_selection.py -k "selection_plan" -q
```

Expected: all planning tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/core/test_selection.py tests/test_test_selection.py
git commit -m "feat(selection): add disabled selection planning"
```

## Task 4: Isolated Scheduling, Resume, And Fingerprints

**Why**

This is the main behavioral change for `file`, `test`, and `auto`.

**Files**
- Modify: `src/pkcs11_check/cli/test_cmd.py`
- Modify: `src/pkcs11_check/core/file_runner.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_file_runner.py`

- [ ] **Step 1: Write failing isolated-path tests**

Add tests in `tests/test_cli.py` for:
- `--isolation test` drops disabled nodeids before scheduling
- `--isolation file` drops fully-disabled files and passes mixed-file deselect data
- `--isolation auto --resume` rebuilds a plan from saved `units`

Add tests in `tests/test_file_runner.py` for:
- state fingerprint changes when baseline fingerprint changes
- resume mismatch triggers when only baseline fingerprint changes

- [ ] **Step 2: Extend runner signatures**

Change `src/pkcs11_check/core/file_runner.py`:

```python
def build_state_fingerprint(
    units: list[str],
    pytest_args: list[str],
    env: Mapping[str, str] | None = None,
    *,
    baseline_fingerprint: str | None = None,
) -> str:
    ...


def run_isolated_pytest_units(
    units: list[str],
    pytest_args: list[str],
    *,
    deselect_by_file: Mapping[str, set[str]] | None = None,
    baseline_fingerprint: str | None = None,
    ...
) -> int:
    ...
```

- [ ] **Step 3: Build selection plans in `test_cmd.py`**

Wire the isolated branch as follows:
- load baseline once
- discover units as today
- collect metadata when file-level planning is needed
- build `DisabledSelectionPlan`
- pass `plan.units`, `plan.deselect_by_file`, `plan.baseline_fingerprint` to `run_isolated_pytest_units()`

Use these rules:
- `test`: no metadata collection needed
- `file`: collect metadata first
- `auto` fresh run: discover auto units, collect metadata, then plan
- `auto` resume: start from `prior_state.units`, then rebuild plan from saved units plus current baseline

- [ ] **Step 4: Verify**

Run:

```bash
uv run python -m pytest tests/test_cli.py tests/test_file_runner.py -k "baseline or fingerprint or resume or isolation" -q
```

Expected: scheduling and fingerprint tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/cli/test_cmd.py src/pkcs11_check/core/file_runner.py tests/test_cli.py tests/test_file_runner.py
git commit -m "feat(isolation): apply disabled baseline to scheduling and resume"
```

## Task 5: Initial File Deselect, Retry Merge, And Escalation Filtering

**Why**

The feature is incomplete unless baseline-disabled tests stay disabled during file retries and adaptive escalation.

**Files**
- Modify: `src/pkcs11_check/core/file_runner.py`
- Modify: `tests/test_file_runner.py`

- [ ] **Step 1: Write failing runner-behavior tests**

Add tests for:
- first file-level subprocess gets `PKCS11_CHECK_DESELECT_FILE` when baseline deselects part of the file
- retry loop starts from the baseline set, then adds completed tests and crash culprits
- `_escalate_current_file()` filters out disabled nodeids before insertion
- disabled nodeids never come back on resume

- [ ] **Step 2: Apply deselect file on first file spawn**

Before the first file-level subprocess run in `run_isolated_pytest_units()`:

```python
unit_deselect = set(deselect_by_file.get(unit, set()))
if unit_deselect:
    deselect_path = write_deselect_file(unit_deselect)
    run_env["PKCS11_CHECK_DESELECT_FILE"] = str(deselect_path)
```

Clean up temp files in `finally`.

- [ ] **Step 3: Merge retry deselection with baseline**

Change the retry loop so it begins with:

```python
deselect_set: set[str] = set(deselect_by_file.get(unit, set()))
```

Then keep unioning:
- completed tests from JSONL
- confirmed culprit nodeids

- [ ] **Step 4: Filter escalated nodeids**

Update `_escalate_current_file()` so new test units are filtered through the current disabled-nodeid set before `_insert_escalated_units()` runs.

- [ ] **Step 5: Verify**

Run:

```bash
uv run python -m pytest tests/test_file_runner.py -k "deselect or escalate or retry or fingerprint" -q
```

Expected: runner baseline behavior is covered and green.

- [ ] **Step 6: Commit**

```bash
git add src/pkcs11_check/core/file_runner.py tests/test_file_runner.py
git commit -m "feat(runner): enforce baseline during retries and escalation"
```

## Task 6: Offline Artifact Helper

**Why**

The runtime feature is separate from candidate generation, but the helper is part of the approved phase-1 design.

**Files**
- Create: `scripts/generate-disabled-tests.py`
- Modify: `src/pkcs11_check/core/test_selection.py`
- Modify: `tests/test_test_selection.py`

- [ ] **Step 1: Write failing artifact-helper tests**

Add tests for:
- extracting exact nodeids from synthetic `report.jsonl`
- preserving parametrized nodeids exactly
- stable sorted output
- filtering by outcome sets such as `failed,error,crashed,timeout`
- correlating `results.json` crash/timeout unit statuses with available `report.jsonl`
- surfacing unresolved crash/timeout cases for manual review instead of inventing nodeids

- [ ] **Step 2: Implement shared helper functions**

Add functions like:

```python
def collect_disabled_candidates(
    artifact_dirs: list[Path],
    *,
    outcomes: set[str],
) -> tuple[list[str], list[str]]:
    ...
```

Return:
- sorted candidate nodeids
- sorted manual-review notes

Reuse shared `report.jsonl` parsing. Do not create a second, drifting outcome mapper.

- [ ] **Step 3: Add the thin script wrapper**

Create `scripts/generate-disabled-tests.py` with:
- `--artifact-dir` repeatable input
- `--outcome` comma-separated filter
- `--output` optional file output
- manual-review notes to stderr

- [ ] **Step 4: Verify**

Run:

```bash
uv run python -m pytest tests/test_test_selection.py -k "artifact or candidate" -q
uv run python scripts/generate-disabled-tests.py --help
```

Expected:
- artifact helper tests pass
- script help shows artifact/outcome/output options

- [ ] **Step 5: Commit**

```bash
git add scripts/generate-disabled-tests.py src/pkcs11_check/core/test_selection.py tests/test_test_selection.py
git commit -m "feat(scripts): add disabled baseline candidate generator"
```

## Task 7: Final Verification

**Files**
- Verify only

- [ ] **Step 1: Run feature meta-tests**

```bash
uv run python -m pytest \
  tests/test_config.py \
  tests/test_test_selection.py \
  tests/test_cli.py \
  tests/test_plugin.py \
  tests/test_file_runner.py \
  -q
```

Expected: all feature-related meta-tests pass.

- [ ] **Step 2: Run lint and types**

```bash
uv run ruff check src/ tests/ scripts/generate-disabled-tests.py
uv run mypy src/
```

Expected: no ruff or mypy failures.

- [ ] **Step 3: Run one smoke validation**

Use one fast target and check both modes:

```bash
uv run pkcs11-check test --module /path/to/module.so --ignore-disabled-tests --isolation none -k test_encrypt -q
uv run pkcs11-check test --module /path/to/module.so --isolation file -k test_encrypt -q
```

Expected:
- opt-out run does not apply production deselection
- default isolated run still works with baseline fingerprinting enabled

- [ ] **Step 4: Final commit**

```bash
git add src/pkcs11_check/config.py src/pkcs11_check/cli/test_cmd.py src/pkcs11_check/plugin.py src/pkcs11_check/core/file_runner.py src/pkcs11_check/core/test_selection.py scripts/generate-disabled-tests.py pkcs11_check.toml config/disabled-tests.txt tests/test_config.py tests/test_cli.py tests/test_plugin.py tests/test_file_runner.py tests/test_test_selection.py
git commit -m "feat: complete production disabled baseline support"
```

## Execution Notes

- Keep the runtime small. No masks, overlays, or invert mode.
- Prefer pure tests in `tests/test_test_selection.py` before touching subprocess behavior.
- If repo `pkcs11_check.toml` changes unrelated test expectations, fix those tests explicitly rather than weakening the default-on contract.
- The helper script is advisory only. The committed baseline file remains authoritative.
