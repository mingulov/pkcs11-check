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
- `longrepr` — structured dict `{reprcrash, reprtraceback, sections, chain}` for failures; string for skips; `None` for passes
- `sections` — `[["Captured stdout call", "..."], ["Captured stderr call", "..."]]`
- `location` — `[filename, lineno, testname]`
- `keywords` — `{"marker_name": 1, ...}`
- `user_properties` — custom properties from `record_property`

### Outcome mapping (CRITICAL)

pytest-reportlog serializes pytest's internal outcome values, which differ from our unified format. `_read_jsonl_results()` MUST perform this mapping:

| Raw JSONL `outcome` | `wasxfail` present? | Unified `outcome` | Notes |
|---------------------|--------------------|--------------------|-------|
| `"passed"` | No | `"passed"` | Normal pass |
| `"passed"` | Yes | `"xpassed"` | Expected failure unexpectedly passed |
| `"failed"` | No | `"failed"` | Normal failure |
| `"failed"` | Yes (strict xfail) | `"failed"` | Strict xfail that passed = failure |
| `"skipped"` | No | `"skipped"` | Normal skip |
| `"skipped"` | Yes | `"xfailed"` | Expected failure that failed as expected |

Source: `_pytest/skipping.py` lines 286-311. Without this mapping, all xfailed tests would be counted as `skipped` and all xpassed as `passed`.

### longrepr handling

`longrepr` in the JSONL can be:
- **A dict** `{reprcrash: {message, path, lineno}, reprtraceback: {reprentries: [...]}, sections: [...], chain: [...]}` — for failures and errors
- **A string** — for skips and xfails (often a tuple repr like `('path', lineno, 'reason')`)
- **`null`/absent** — for passes

`_read_jsonl_results()` must flatten dict longrepr to a string for `results.json`:
- Extract `reprcrash.message` as the summary
- Concatenate `reprtraceback` entries for full traceback text
- Store as a string in the unified format

### Handling different `when` phases

- **`when=call`** — primary source of test outcome, duration, wasxfail, longrepr
- **`when=setup` with `outcome=error`** — fixture failure; count as `error`, not `failed`. If a session-scoped fixture fails, many tests get `setup/error` — deduplicate by reporting the fixture error once, then count remaining as `error` in counts only
- **`when=setup` with `outcome=skipped`** — test skipped during setup (e.g., `pytest.skip()` in fixture). No `when=call` record follows. Count as `skipped`
- **`when=teardown`** — ignore for outcome determination; only used to confirm test completion for crash culprit identification

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

Note: `outcome` is the MAPPED value (`"xfailed"`), not the raw JSONL value (`"skipped"`).

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
4. If no such nodeid exists (crash during collection or between tests), fall back to: first nodeid from `collect_pytest_nodeids` that has no `TestReport` at all. This collection fallback runs at most ONCE and is cached for subsequent iterations.

### Exit conditions

- File passes → done
- No tests remaining → done (all crashed)
- Max iterations reached (`max_deselect_iterations`, hardcoded 10) → escalate remaining tests to per-test isolation via `_escalate_current_file()` (existing behavior as final fallback). The `"escalated"` status is preserved for this case.
- Collection error (`CollectReport` with `outcome=error`, no `TestReport` entries) → do NOT retry, record as error

### State persistence during iterative deselect

Each completed iteration's results are saved to `state.json` immediately. The deselect set (completed nodeids + crash culprits) is accumulated in memory during the loop. If the runner is interrupted mid-iteration:
- All prior iterations' results are in `state.json`
- The current iteration's partial results are in the JSONL temp file
- On `--resume`, the unit is re-attempted from scratch (iteration 1) but already-recorded results from state.json prevent duplicates via `_RESUME_COMPLETE_STATUSES`

This means interrupted iterations may re-run some tests, but it is safe because:
- Tests use `try/finally` for cleanup (project convention)
- The deselect set from prior iterations is NOT persisted — it is rebuilt from state.json results on resume

### Merging results across iterations

Each iteration's JSONL contains results for the tests that ran. The runner merges:
- Iteration 1: tests 1-4 passed, test 5 crashed (from JSONL partial + confirmation run)
- Iteration 2: tests 6-41 passed, test 42 crashed
- Iteration 3: tests 43-200 passed

All merged into one unit in `results.json` with combined counts and the full `tests` array.

### max_crashes_per_file (KEPT, not renamed)

Keep the existing `max_crashes_per_file` flag with its current semantics: limits how many different tests in one file can crash before the iterative deselect loop gives up and escalates remaining tests to per-test isolation. Default stays 3.

This is distinct from `max_deselect_iterations` (hardcoded 10) which is a safety cap on the loop itself.

### OS command-line length limits

With many deselected tests, `--deselect=<nodeid>` args accumulate. For parametrized tests with long nodeids (e.g., Wycheproof), this could approach OS limits.

Guard: if total deselect arg length exceeds 100KB, stop the iterative deselect loop and escalate remaining tests to per-test isolation. pytest does not support `--deselect-file`, so this is the only safe fallback.

### Token state across iterations

PKCS#11 token objects created by tests in iteration 1 remain on the token when iteration 2 runs (subprocesses share the token database). This can cause:
- Leaked objects from crashed tests (no `finally` cleanup ran)
- Unexpected objects visible to iteration 2 tests

This is acceptable because:
- Project convention: tests use `try/finally obj.destroy()`
- Crashed tests will have leaked objects regardless of recovery strategy
- The alternative (per-test isolation) has the same token state across subprocess boundaries

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

The `report.jsonl` concatenation streams per-unit JSONL files sequentially into a temp file, then does an atomic rename. No in-memory accumulation of the full content.

## Future: Batch Isolation Mode

Once JSONL infrastructure is in place, a new `--isolation batch` (or new `auto` default) becomes possible:

1. Run ALL files in one subprocess (like `--isolation none` but crash-safe)
2. JSONL streams results — completed files are tracked by nodeid prefix
3. On crash: read JSONL, identify completed files + crash culprit in current file
4. Retry from crashed file onward, deselecting all completed files + crash culprit
5. Failed/xfailed tests get a confirmation re-run in isolated subprocess (fresh PKCS#11 session) to verify the result isn't from stale token state

Benefits: 1 subprocess for 195 files instead of 195 (~175s startup saved). Only crashes/failures need extra subprocesses. Current `--isolation file` stays as conservative option.

This layers directly on top of the JSONL + iterative deselect infrastructure from this spec.

## Files to Modify

| File | Change |
|------|--------|
| `core/file_runner.py` | Replace `--json-report` with `--report-log` in subprocess cmd. Strip `--report-log` in `_collection_args()`. New `_read_jsonl_results()` with outcome mapping (skipped+wasxfail→xfailed, passed+wasxfail→xpassed) and longrepr flattening (dict→string). New `_identify_crash_culprit()` from JSONL. Rewrite crash handler to iterative-deselect loop with `max_crashes_per_file` exit + `max_deselect_iterations` safety cap + 100KB deselect arg guard. Keep `_escalate_current_file()` as final fallback. Update `write_isolated_json_report()` to build from JSONL data. Remove `_extract_xfail_reason()`, `_deselect_args_for_crash()`, `postprocess_json_report_to_unified()`. Skip JSONL for test-level units (same perf guard as current json-report). |
| `plugin.py` | Conditionally register `--report-log` ONLY when `--p11-module` is set AND output is json. Must not affect meta-tests or external plugin consumers. |
| `cli/test_cmd.py` | Remove `--json-report` injection from `_build_pytest_args`. Pass JSONL artifact path through to runner. Concatenate per-unit JONLs into final `report.jsonl` (streaming, atomic rename). |
| `compliance_report.py` | Document that only unified format (`kind=test-run`) is supported. Raw json-report format (format 2 in `_parse_test_results`) will break when pytest-json-report is removed — this is acceptable (no known external consumers). |
| `pyproject.toml` | Promote `pytest-reportlog` from dev to main dependencies. Remove `pytest-json-report`. |
| `docker/run-pkcs11-check.sh` | No changes needed (uses `PKCS11_CHECK_MAX_CRASHES_PER_FILE` which stays). |
| `tests/test_file_runner.py` | Update mocks: write JSONL files instead of json-report. Add tests for: outcome mapping (xfailed/xpassed/strict-xfail), structured longrepr flattening, iterative deselect with multiple crashes, CollectReport errors (no retry), setup-skip (no call record), fixture error deduplication, resume after interrupted iteration, 100KB deselect guard, `--report-log` already in user args. |

## Guards

- **JSONL missing** (crash during collection before any test runs, or crash during setup before first test): fall back to returncode-based status, no per-test data. If `CollectReport` with `outcome=error` exists, record collection error.
- **JSONL truncated** (crash mid-write): skip lines that fail `json.loads`. At most one line lost due to line-buffered I/O.
- **Temp file cleanup**: always delete per-unit JSONL temps after reading, even on crash (use try/finally).
- **75K vectors**: `report.jsonl` for 75K tests is ~100MB (passing tests have ~500 bytes/line × 3 phases). `results.json` stays compact. Acceptable for artifact storage.
- **`--isolation none` + `--report-log`**: if user already passed `--report-log` via extra args, don't inject a second one.
- **`--isolation test`**: do NOT create JSONL temp files (75K files unacceptable). Synthesize per-test results from `FileRunResult` status/returncode.
- **Fixture errors**: session-scoped fixture failure produces N duplicate `TestReport(when=setup, outcome=error)` entries. Deduplicate: report fixture error once, count remaining as `error` in counts only.
- **Resume compatibility**: changing subprocess args (`--report-log` vs `--json-report`) changes the state fingerprint. During migration (Phase 1), both are active, so fingerprint includes both. Users with in-progress `--resume` runs from before migration will see a fingerprint mismatch and start fresh — document this in release notes.
- **Partial execution records**: a test with `when=setup` passed but process crashed during `when=call` has a partial record. It is the crash culprit. Record it with the confirmation run result (crashed if confirmation crashes, passed if it passes in isolation).

## Migration Phases

1. **Phase 1**: Add `--report-log` injection alongside existing `--json-report` (both active). New `_read_jsonl_results()` with outcome mapping and longrepr flattening. Promote `pytest-reportlog` to main deps. Strip `--report-log` from `_collection_args()`.
2. **Phase 2**: Iterative deselect crash recovery using JSONL (replaces `_deselect_args_for_crash` and single-retry approach). Keep `_escalate_current_file()` as final fallback when `max_crashes_per_file` or `max_deselect_iterations` or 100KB deselect limit is reached.
3. **Phase 3**: Activate JSONL for `--isolation none` via conditional `plugin.py` registration. Replace `postprocess_json_report_to_unified` with JSONL aggregation.
4. **Phase 4**: Remove `pytest-json-report` dependency and all old extraction code. Remove json-report injection from `_build_pytest_args`.
5. **Phase 5**: Write `report.jsonl` artifact (streaming concatenation, atomic rename).

## Required test cases

1. **Outcome mapping**: xfailed (`skipped`+`wasxfail`→`xfailed`), xpassed (`passed`+`wasxfail`→`xpassed`), strict xfail (`failed`+`wasxfail`→`failed`), regular skip, regular pass, regular fail
2. **longrepr flattening**: dict longrepr (with reprcrash/reprtraceback) → string, string longrepr → passthrough, null longrepr → omit
3. **Iterative deselect**: 2 crashes in same file, verify 3 subprocesses (file+crash1+retry) not 200
4. **CollectReport error**: import error → no retry, record error
5. **Setup skip**: test skipped in fixture → counted as skipped, not crash culprit
6. **Fixture error dedup**: session fixture failure → 1 error detail + N-1 count-only
7. **100KB deselect guard**: large parametrized file → fallback to per-test isolation
8. **`--report-log` dedup**: user passes `--report-log` in extra args → don't inject second
9. **Resume after crash iteration**: interrupt mid-iteration → resume works correctly
10. **Confirmation run passes**: crash culprit passes in isolation → record as "passed", still deselect

## Implementation instruction

```
Read docs/superpowers/specs/2026-03-21-jsonl-reporting-design.md
and implement in phases:
- Phase 1: Add --report-log to subprocess cmd, new _read_jsonl_results()
  with outcome mapping and longrepr flattening, promote pytest-reportlog
  to main deps, strip from _collection_args. Keep --json-report as fallback.
- Phase 2: Iterative deselect crash recovery using JSONL.
  Crash culprit from JSONL event order (not collection order).
  Confirmation run per crasher. Deselect ALL completed + crashers on retry.
  max_crashes_per_file + max_deselect_iterations + 100KB deselect guard.
  Keep _escalate_current_file as final fallback.
- Phase 3: Activate for --isolation none via conditional plugin.py.
- Phase 4: Remove pytest-json-report, remove old extraction code.
- Phase 5: Write report.jsonl artifact (streaming concat, atomic rename).
```
