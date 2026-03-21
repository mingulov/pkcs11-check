# JSONL-Based Test Reporting — Design Spec

## Problem

pkcs11-check uses pytest-json-report for per-test results. It writes the entire JSON at process exit, so:

1. **Crash = total data loss** — subprocess segfault means no report at all
2. **No `wasxfail` field** — pytest-json-report doesn't serialize it; we parse longrepr with regex
3. **No timestamps** — can't do timeline analysis
4. **No crash identification** — can't tell which test caused the crash
5. **Escalation to per-test isolation is expensive** — a file with 200 tests and 1 crasher spawns 200 subprocesses

## Solution

Replace pytest-json-report with pytest-reportlog (JSONL). Each test result is written as a JSON line, flushed immediately. Crashes leave a parseable partial file.

## Architecture

### One source, two artifacts

- `report.jsonl` — raw per-test JSONL from pytest-reportlog, kept as artifact
- `results.json` — aggregated unified report (current format, built from JSONL)

### Works identically in all isolation modes

| Mode | How JSONL is written | Post-processing |
|------|---------------------|-----------------|
| `--isolation auto/file` | Each subprocess writes a tmp JSONL via `--report-log=<tmpfile>` | Runner reads each, aggregates into `results.json`, concatenates into `report.jsonl` |
| `--isolation test` | Each subprocess writes a 1-test JSONL | Same aggregation |
| `--isolation none` | Single pytest run writes one JSONL (activated via `plugin.py`) | Post-process into `results.json` |

### Replaces

- `pytest-json-report` dependency (remove from pyproject.toml)
- `--json-report` / `--json-report-file` injection in subprocess cmd
- `_extract_per_unit_test_detail()` — replaced by `_read_jsonl_results()`
- `postprocess_json_report_to_unified()` — replaced by JSONL-based aggregation
- `_extract_xfail_reason()` — no longer needed, `wasxfail` is a direct field

## JSONL Format (from pytest-reportlog)

Each line is a JSON object with `$report_type`. Relevant types:

```jsonl
{"$report_type":"SessionStart","pytest_version":"9.0.2"}
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
   - Completed: tests 1-4 (have TestReport with when=call)
   - Crash culprit: test #5 (first without a call report)
3. Run test #5 alone (isolation=test) → confirm crash → record as "crashed"
4. Retry file with --deselect tests#1-5 (195 tests) → crash after test #41
5. Read partial JSONL: tests 6-41 completed, test #42 = new culprit
6. Run test #42 alone → confirm crash → record as "crashed"
7. Retry file with --deselect tests#1-5,tests#6-42 (158 tests) → passes
8. Merge results from all iterations
```

**Key:** each retry deselects ALL already-completed tests AND all confirmed
crashers. Tests are never re-run — their results are already captured in the
JSONL from the iteration where they completed. This avoids re-running
passed tests (which could fail on second run due to leftover token state).

### Exit conditions

- File passes → done
- No tests remaining → done (all crashed)
- Never escalates to per-test — just iterative deselect + single-test confirmation

### Merging results across iterations

Each iteration's JSONL contains results for the tests that ran. The runner merges:
- Iteration 1: tests 1-4 passed, test 5 crashed (from JSONL partial + confirmation run)
- Iteration 2: tests 6-41 passed, test 42 crashed
- Iteration 3: tests 43-200 passed

All merged into one unit in `results.json` with combined counts and the full `tests` array.

### max_crashes_per_test

The existing `max_crashes_per_file` is renamed to `max_crashes_per_test`. It limits how many times a single crashing test is retried in its confirmation run (default: 1 — just confirm the crash once, don't retry). This does NOT limit how many tests in a file can crash.

## Artifact Layout

```
artifacts/<provider>/
  console.log      # tee'd console output (unchanged)
  results.json     # aggregated unified report (enriched with new fields)
  report.jsonl     # raw per-test JSONL from all subprocesses (new)
  state.json       # resume state (unchanged)
  policy.json      # isolation policy (unchanged)
```

## Files to Modify

| File | Change |
|------|--------|
| `core/file_runner.py` | Replace `--json-report` with `--report-log` in subprocess cmd. New `_read_jsonl_results()` replaces `_extract_per_unit_test_detail()`. New `_identify_crash_culprit()` from JSONL. Rewrite crash handler to iterative-deselect loop. Update `write_isolated_json_report()` to build from JSONL data. Remove `_extract_xfail_reason()`. Remove `postprocess_json_report_to_unified()`. |
| `plugin.py` | Register `--report-log` automatically for `--isolation none` runs |
| `cli/test_cmd.py` | Pass JSONL artifact path through to runner. Concatenate per-unit JONLs into final `report.jsonl` |
| `compliance_report.py` | No change — reads `results.json` which keeps same structure |
| `pyproject.toml` | Remove `pytest-json-report`, keep `pytest-reportlog` |
| `tests/test_file_runner.py` | Update mocks: write JSONL files instead of json-report. Add tests for crash recovery loop. |

## Guards

- **JSONL missing** (crash during setup before any test runs): fall back to returncode-based status, no per-test data
- **JSONL truncated** (crash mid-write): ignore the last incomplete line (json.loads will fail, skip it)
- **Temp file cleanup**: delete per-unit JSONL temps after reading, even on crash
- **75K vectors**: `report.jsonl` for 75K tests is ~50MB — acceptable for artifact storage. `results.json` stays compact (only non-passing in `tests` array).
- **`--isolation none` + `--report-log`**: if user already passed `--report-log` via extra args, don't add a second one

## Migration

1. Add `--report-log` injection alongside existing `--json-report` (both active)
2. Switch `_extract_per_unit_test_detail` to prefer JSONL, fall back to json-report
3. Once validated, remove json-report injection and dependency
4. Rename `max_crashes_per_file` → `max_crashes_per_test`

## Implementation instruction

```
Read docs/superpowers/specs/2026-03-21-jsonl-reporting-design.md
and implement in phases:
- Phase 1: Add --report-log to subprocess cmd, new _read_jsonl_results(),
  wire into results.json. Keep --json-report as fallback.
- Phase 2: Iterative deselect crash recovery using JSONL.
- Phase 3: Remove pytest-json-report, remove old extraction code.
- Phase 4: Activate for --isolation none via plugin.py.
- Phase 5: Write report.jsonl artifact.
```
