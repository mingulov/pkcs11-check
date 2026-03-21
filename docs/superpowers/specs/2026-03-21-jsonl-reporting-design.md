# JSONL-Based Test Reporting — Design Spec

## Problem

pkcs11-check uses pytest-json-report for per-test results. It writes the entire JSON at process exit, so:

1. **Crash = total data loss** — subprocess segfault means no report at all
2. **No `wasxfail` field** — pytest-json-report doesn't serialize it; we parse longrepr with regex
3. **No timestamps** — can't do timeline analysis
4. **No crash identification** — can't tell which test caused the crash
5. **Escalation to per-test isolation is expensive** — a file with 200 tests and 1 crasher spawns 200 subprocesses

## Solution

Replace pytest-json-report with pytest-reportlog (JSONL). Each test result is written as a JSON line, flushed immediately (line-buffered). Crashes leave a parseable partial file.

## Architecture

### One source, two artifacts

- `report.jsonl` — raw per-test JSONL from pytest-reportlog, kept as artifact
- `results.json` — aggregated unified report (current format, built from JSONL)

### Works identically in all isolation modes

| Mode | How JSONL is written | Post-processing |
|------|---------------------|-----------------|
| `--isolation auto/file` | Each subprocess writes a tmp JSONL via `--report-log=<tmpfile>` | Runner reads each, aggregates into `results.json`, concatenates into `report.jsonl` |
| `--isolation test` | No per-test JSONL (75K temp files unacceptable) — synthesize from FileRunResult | Same aggregation |
| `--isolation none` | Single pytest run writes one JSONL (activated conditionally via `plugin.py`) | Post-process into `results.json` |

### Replaces

- `pytest-json-report` dependency (remove from pyproject.toml, promote `pytest-reportlog` to main deps)
- `--json-report` / `--json-report-file` injection in subprocess cmd
- `_extract_per_unit_test_detail()` — replaced by `_read_jsonl_results()`
- `postprocess_json_report_to_unified()` — replaced by JSONL-based aggregation
- `_extract_xfail_reason()` — no longer needed, `wasxfail` is a direct field
- `_deselect_args_for_crash()` — replaced by JSONL-based crash identification

## JSONL Format (from pytest-reportlog)

Each line is a JSON object with `$report_type`. Relevant types:

```jsonl
{"$report_type":"SessionStart","pytest_version":"9.0.2"}
{"$report_type":"CollectReport","nodeid":"test_foo.py","outcome":"passed",...}
{"$report_type":"TestReport","nodeid":"test_foo.py::test_bar","when":"setup","outcome":"passed","duration":0.001,...}
{"$report_type":"TestReport","nodeid":"test_foo.py::test_bar","when":"call","outcome":"passed","duration":0.12,"start":1711042800.1,"stop":1711042800.22,"sections":[["Captured stdout call","output..."]],...}
{"$report_type":"TestReport","nodeid":"test_foo.py::test_bar","when":"teardown","outcome":"passed","duration":0.001,...}
{"$report_type":"TestReport","nodeid":"test_foo.py::test_baz","when":"call","outcome":"skipped","wasxfail":"known bug","duration":0.04,"longrepr":{...},...}
{"$report_type":"SessionFinish","exitstatus":0}
```

Key fields per TestReport (when=call):
- `nodeid`, `outcome`, `duration`, `start`, `stop`
- `wasxfail` — direct xfail reason string (only on xfailed/xpassed tests)
- `longrepr` — structured: `{reprcrash, reprtraceback, sections, chain}`
- `sections` — `[["Captured stdout call", "..."], ["Captured stderr call", "..."]]`
- `location` — `[filename, lineno, testname]`
- `keywords` — `{"marker_name": 1, ...}`
- `user_properties` — custom properties from `record_property`

### Handling different `when` phases

- **`when=call`** — primary source of test outcome, duration, wasxfail, longrepr
- **`when=setup` with `outcome=error`** — fixture failure; count as `error`, not `failed`. If a session-scoped fixture fails, many tests get `setup/error` — deduplicate by reporting the fixture error once, then count remaining as `error` in counts only
- **`when=setup` with `outcome=skipped`** — test skipped during setup (e.g., `pytest.skip()` in fixture). No `when=call` record follows. Count as `skipped`
- **`when=teardown`** — ignore for outcome determination; only used to confirm test completion

### CollectReport handling

- `CollectReport` with `outcome=passed` — skip (just collection metadata)
- `CollectReport` with `outcome=error` — import/syntax error in test file. Record as `error` in counts with longrepr. Do NOT retry via iterative deselect (not a crash)
- Skip `CollectReport` entries when counting to avoid doubling JSONL size for parametrized tests

## Per-test entry in results.json (enriched)

```json
{
  "nodeid": "test_sign.py::TestRSA::test_pss",
  "outcome": "xfailed",
  "duration": 0.045,
  "start": 1711042800.3,
  "wasxfail": "Kryoptic CKR_DEVICE_ERROR",
  "longrepr": "full traceback text...",
  "location": ["test_sign.py", 42, "TestRSA.test_pss"],
  "stdout": "captured stdout...",
  "stderr": "captured stderr..."
}
```

### Inclusion policy for results.json `tests` array

- **Non-passing** (failed, xfailed, xpassed, error, crashed): full detail
- **Passing**: counted in `counts` only, not listed (keeps 75K-vector files compact)
- **Crashed**: synthetic entry with `"outcome": "crashed"`

The raw `report.jsonl` has everything including passing tests.

## Crash Recovery: Iterative Deselect

When a file-level subprocess crashes, instead of escalating to per-test isolation:

### Flow

```
1. Run file (200 tests) → crash after test #4
2. Read partial JSONL:
   - Completed: tests with TestReport(when=call) + TestReport(when=teardown)
   - Crash culprit: last test with when=setup (or when=call) but no when=teardown
     (uses JSONL event order, NOT collection order)
3. Run crash culprit ALONE (isolation=test) → confirm crash → record as "crashed"
   - If confirmation PASSES: record as "passed", still deselect from retry
     (crash was likely caused by interaction with a previous test)
4. Retry file with --deselect for ALL completed tests + culprit (195 tests)
   → crash after test #41
5. Read JSONL, identify new culprit (test #42)
6. Run test #42 alone → confirm → record result
7. Retry file with --deselect for ALL completed + ALL culprits (158 tests) → passes
8. Merge results from all iterations
```

**Key:** each retry deselects ALL already-completed tests AND all confirmed
crashers. Tests are never re-run — their results are already captured in the
JSONL from the iteration where they completed. This avoids re-running
passed tests (which could fail on second run due to leftover token state).

### Crash culprit identification

Uses **JSONL event order** (not collection order — tests may be reordered by plugins):
1. Scan JSONL for all `TestReport` entries
2. Build per-nodeid state: has `setup`? has `call`? has `teardown`?
3. Crash culprit = the nodeid that has `setup` started but no `teardown` completed
4. If no such nodeid exists (crash during collection or between tests), fall back to: first nodeid from `collect_pytest_nodeids` that has no `TestReport` at all

### Exit conditions

- File passes → done
- No tests remaining → done (all crashed)
- Max iterations reached (`max_deselect_iterations`, default 10) → record remaining as "unknown" and stop. This prevents infinite loops if culprit identification is wrong (e.g., crash is environmental, not test-specific)
- Collection error (`CollectReport` with `outcome=error`, no `TestReport` entries) → do NOT retry, record as error

### Merging results across iterations

Each iteration's JSONL contains results for the tests that ran. The runner merges:
- Iteration 1: tests 1-4 passed, test 5 crashed (from JSONL partial + confirmation run)
- Iteration 2: tests 6-41 passed, test 42 crashed
- Iteration 3: tests 43-200 passed

All merged into one unit in `results.json` with combined counts and the full `tests` array.

### max_crashes_per_test (renamed from max_crashes_per_file)

Limits how many times a single crashing test is retried in its confirmation run (default: 1 — just confirm the crash once). Does NOT limit how many tests in a file can crash. The CLI flag `--max-crashes-per-file` is renamed to `--max-crashes-per-test`; the old name is kept as a deprecated alias for backward compatibility. `PKCS11_CHECK_MAX_CRASHES_PER_FILE` env var also kept as alias.

### OS command-line length limits

With many deselected tests, `--deselect=<nodeid>` args accumulate. For parametrized tests with long nodeids, this could approach OS limits (~2MB on Linux). Guard: if total deselect arg length exceeds 100KB, write nodeids to a temp file and use `--deselect-file=<path>` instead (or fall back to per-test isolation if pytest doesn't support `--deselect-file`).

## SIGSEGV and JSONL flush behavior

pytest-reportlog uses Python line-buffered I/O (`buffering=1`). On SIGSEGV, the OS kills the process without running Python finalizers. Line-buffered mode flushes on each `\n` write, so at most the last incomplete line is lost. The crash culprit identification may be off by one test in rare cases — the retry loop handles this (the retry will crash again, identifying the real culprit in the next iteration).

## Artifact Layout

```
artifacts/<provider>/
  console.log      # tee'd console output (unchanged)
  results.json     # aggregated unified report (enriched with new fields)
  report.jsonl     # raw per-test JSONL from all subprocesses (new)
  state.json       # resume state (unchanged)
  policy.json      # isolation policy (unchanged)
```

The `report.jsonl` concatenation uses a temp file + atomic rename to prevent partial artifacts on interruption.

## Files to Modify

| File | Change |
|------|--------|
| `core/file_runner.py` | Replace `--json-report` with `--report-log` in subprocess cmd. Strip `--report-log` in `_collection_args()`. New `_read_jsonl_results()` replaces `_extract_per_unit_test_detail()`. New `_identify_crash_culprit()` from JSONL. Rewrite crash handler to iterative-deselect loop. Update `write_isolated_json_report()` to build from JSONL data. Remove `_extract_xfail_reason()`, `_deselect_args_for_crash()`, `postprocess_json_report_to_unified()`. Skip JSONL for test-level units (same perf guard as current json-report). |
| `plugin.py` | Conditionally register `--report-log` ONLY when `--p11-module` is set AND output is json. Must not affect meta-tests or external plugin consumers. |
| `cli/test_cmd.py` | Remove `--json-report` injection from `_build_pytest_args`. Pass JSONL artifact path through to runner. Concatenate per-unit JONLs into final `report.jsonl`. |
| `compliance_report.py` | Document that only unified format (`kind=test-run`) is supported. Raw json-report format (format 2 in `_parse_test_results`) will break when pytest-json-report is removed — this is acceptable (no known external consumers). |
| `pyproject.toml` | Promote `pytest-reportlog` from dev to main dependencies. Remove `pytest-json-report`. |
| `docker/run-pkcs11-check.sh` | Keep `PKCS11_CHECK_MAX_CRASHES_PER_FILE` as alias for renamed flag. |
| `tests/test_file_runner.py` | Update mocks: write JSONL files instead of json-report. Add tests for iterative deselect crash recovery. Update fingerprint tests (args change). |

## Guards

- **JSONL missing** (crash during collection before any test runs, or crash during setup before first test): fall back to returncode-based status, no per-test data. If `CollectReport` with `outcome=error` exists, record collection error.
- **JSONL truncated** (crash mid-write): skip lines that fail `json.loads`. At most one line lost due to line-buffered I/O.
- **Temp file cleanup**: always delete per-unit JSONL temps after reading, even on crash (use try/finally).
- **75K vectors**: `report.jsonl` for 75K tests is ~50MB (passing tests have ~200 bytes/line × 3 phases). `results.json` stays compact. Acceptable for artifact storage.
- **`--isolation none` + `--report-log`**: if user already passed `--report-log` via extra args, don't inject a second one.
- **`--isolation test`**: do NOT create JSONL temp files (75K files unacceptable). Synthesize per-test results from `FileRunResult` status/returncode.
- **Fixture errors**: session-scoped fixture failure produces N duplicate `TestReport(when=setup, outcome=error)` entries. Deduplicate: report fixture error once, count remaining as `error` in counts only.
- **Resume compatibility**: changing subprocess args (`--report-log` vs `--json-report`) changes the state fingerprint. During migration (Phase 1), both are active, so fingerprint includes both. Users with in-progress `--resume` runs from before migration will see a fingerprint mismatch and start fresh — document this in release notes.
- **Partial execution records**: a test with `when=setup` passed but process crashed during `when=call` has a partial record. It is the crash culprit. Record it with the confirmation run result (crashed if confirmation crashes, passed if it passes in isolation).

## Migration Phases

**Critical ordering: Phase 4 must complete before or simultaneously with Phase 3.** Removing pytest-json-report before JSONL is active for `--isolation none` would break that mode.

1. **Phase 1**: Add `--report-log` injection alongside existing `--json-report` (both active). New `_read_jsonl_results()`. Promote `pytest-reportlog` to main deps. Strip `--report-log` from `_collection_args()`.
2. **Phase 2**: Iterative deselect crash recovery using JSONL (replaces `_deselect_args_for_crash` and per-test escalation). Add `max_deselect_iterations`.
3. **Phase 4** (before 3!): Activate JSONL for `--isolation none` via conditional `plugin.py` registration. Replace `postprocess_json_report_to_unified` with JSONL aggregation.
4. **Phase 3**: Remove `pytest-json-report` dependency and all old extraction code. Remove json-report injection from `_build_pytest_args`.
5. **Phase 5**: Write `report.jsonl` artifact. Atomic concatenation. Rename `max_crashes_per_file` → `max_crashes_per_test` with backward-compatible alias.

## Implementation instruction

```
Read docs/superpowers/specs/2026-03-21-jsonl-reporting-design.md
and implement in phases:
- Phase 1: Add --report-log to subprocess cmd, new _read_jsonl_results(),
  promote pytest-reportlog to main deps, strip from _collection_args.
  Keep --json-report as fallback.
- Phase 2: Iterative deselect crash recovery using JSONL.
  Crash culprit from JSONL event order (not collection order).
  Confirmation run per crasher. Deselect ALL completed + crashers on retry.
- Phase 4: Activate for --isolation none via conditional plugin.py.
- Phase 3: Remove pytest-json-report, remove old extraction code.
- Phase 5: Write report.jsonl artifact. Rename max_crashes flag with alias.
```
