# Unified Test Results Architecture — Design Brief

## Problem

pkcs11-check has two incompatible result formats depending on isolation mode:

1. **`--isolation none`**: Uses pytest-json-report directly → per-test outcomes with nodeid, outcome (passed/failed/xfailed/skipped), duration, xfail reasons
2. **`--isolation auto/file/test`**: Custom FileRunResult → per-unit (file-level) outcomes with only status/returncode/duration/stdout/stderr. No per-test breakdown. xfailed tests are invisible (counted as "passed").

This makes it impossible to:
- See which tests xfailed and why across isolation modes
- Generate consistent compliance reports regardless of isolation mode
- Compare results between isolation modes
- Track xfail regressions (tests that stop xfailing = bugs got fixed)

## Goal

A single, unified results format that works identically regardless of isolation mode. Every test run produces the same JSON structure with per-test outcomes.

## Current State

### FileRunResult (isolated runner)
```python
@dataclass(frozen=True)
class FileRunResult:
    target: str        # file or test nodeid
    status: str        # "passed" | "failed" | "crashed" | "timeout" | "empty"
    returncode: int
    duration_s: float
    stdout: str = ""   # captured, only for non-passing
    stderr: str = ""
```

### pytest-json-report (non-isolated)
```json
{
  "tests": [
    {
      "nodeid": "test_sign.py::TestRSA::test_pss",
      "outcome": "passed",
      "duration": 0.123,
      "setup": {"outcome": "passed"},
      "call": {"outcome": "passed"},
      "teardown": {"outcome": "passed"}
    },
    {
      "nodeid": "test_sign.py::TestRSA::test_x509",
      "outcome": "xfailed",
      "wasxfail": "Kryoptic CKR_DEVICE_ERROR",
      "duration": 0.045
    }
  ],
  "summary": {"passed": 12, "failed": 0, "xfailed": 3}
}
```

## Proposed Design: Option B (pytest-json-report per subprocess)

### Key Changes

1. **Each isolated subprocess writes a per-unit JSON report** via `--json-report --json-report-file=<tmpfile>` added to the subprocess command
2. **After subprocess completes**, the runner reads the temp JSON and extracts per-test outcomes
3. **FileRunResult gains new fields**: `tests` (per-test outcomes), `passed`/`failed`/`skipped`/`xfailed` counts
4. **The aggregated results.json** merges all per-unit results into a unified format that matches pytest-json-report's structure
5. **compliance_report.py** reads ONE format regardless of isolation mode

### Guards

- **File-granularity only**: For per-test isolation (`--isolation test`), each subprocess runs ONE test — the JSON report is the result itself. For file-granularity, each subprocess runs a full file.
- **Crash handling**: If subprocess crashes (segfault), the JSON file may not exist. Fall back to returncode-based status + captured stdout/stderr.
- **Temp file cleanup**: Always delete temp JSON after reading, even on crash.
- **Backward compatibility**: The new `tests` field is optional in the JSON. Old results without it still work.

### Unified Output Format

```json
{
  "tool": "pkcs11-check",
  "kind": "test-run",
  "summary": {
    "passed": 969,
    "failed": 80,
    "skipped": 585,
    "xfailed": 15,
    "xpassed": 0,
    "error": 0,
    "total": 1649
  },
  "units": [
    {
      "target": "src/pkcs11_check/testcases/test_sign.py",
      "status": "passed",
      "returncode": 0,
      "duration_s": 1.2,
      "counts": {"passed": 12, "skipped": 5, "xfailed": 3},
      "tests": [
        {"nodeid": "test_sign.py::TestRSA::test_pss", "outcome": "passed", "duration": 0.1},
        {"nodeid": "test_sign.py::TestRSA::test_x509", "outcome": "xfailed",
         "wasxfail": "Kryoptic CKR_DEVICE_ERROR", "duration": 0.04}
      ]
    },
    {
      "target": "src/pkcs11_check/testcases/test_encrypt.py",
      "status": "failed",
      "returncode": 1,
      "duration_s": 2.3,
      "stdout": "... pytest output with tracebacks ...",
      "stderr": "",
      "counts": {"passed": 8, "failed": 2, "xfailed": 1},
      "tests": [
        {"nodeid": "test_encrypt.py::test_aes_ctr", "outcome": "failed",
         "longrepr": "AssertionError: ..."}
      ]
    }
  ]
}
```

### Design Questions to Resolve

1. **Should `tests` array include ALL tests or only non-passing?** Including all tests for 75K Wycheproof vectors would create a huge JSON. Options:
   - (a) All tests always → honest but potentially 50MB JSON
   - (b) Only non-passing (failed, xfailed, xpassed, error) → compact, useful
   - (c) Configurable via `--report-detail full|failures|summary`

2. **How to handle `--isolation test`?** Each subprocess runs ONE test. The per-unit JSON report has exactly one test. Should these be aggregated back into per-file groups in the final report?

3. **Should the non-isolated path (`--isolation none`) also produce the unified format?** Currently it uses pytest-json-report's native format. Should we post-process it into the unified format for consistency?

4. **How does this interact with the existing `state.json` (resumable state)?** State.json stores FileRunResult per unit for resume. Adding per-test data to state.json would bloat it. Keep state.json minimal (current behavior) and put the rich data only in results.json?

5. **Collection-phase filtering**: The `_collection_args` function strips `--json-report` flags. Need to ensure per-unit JSON goes to a unique temp file that doesn't conflict.

### Implementation Scope

Files to modify:
- `src/pkcs11_check/core/file_runner.py` — FileRunResult, subprocess invocation, report writing
- `src/pkcs11_check/compliance_report.py` — read unified format
- `tests/test_file_runner.py` — update mocks for new subprocess args
- `docker/run-pkcs11-check.sh` — no changes needed (transparent)

Estimated: ~100-150 lines of new code, ~30 lines of test updates.

### Risks

- **Performance**: Writing + reading a JSON file per subprocess adds I/O overhead. For 195 file units, that's 195 temp files. For 75K test units, it's 75K files (unacceptable). Guard: only enable for file-granularity.
- **pytest-json-report compatibility**: If the subprocess crashes mid-write, the JSON may be truncated. Guard: wrap JSON reading in try/except.
- **State file bloat**: Don't add per-test data to state.json. Only results.json gets the rich data.

## Instruction for Implementation Session

```
Read docs/superpowers/specs/2026-03-21-unified-test-results-design-brief.md
and implement Option B. Resolve design questions as follows:
- Question 1: Option (b) — only non-passing tests in the tests array
- Question 2: Aggregate back into per-file groups
- Question 3: Yes — post-process pytest-json-report into unified format
- Question 4: Keep state.json minimal, rich data only in results.json
- Question 5: Use unique tempfile names per unit
```
