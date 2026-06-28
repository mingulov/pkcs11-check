# Task A3C1 Report — Provenance Wiring for Isolated Path

## Status: DONE

## What was fixed

### FIX 1 — Thread provenance through isolated writer path

Call chain wired:

1. `_build_isolated_json_payload` (file_runner.py ~line 773) — added `provenance: dict[str, Any] | None = None` param; after the payload dict is built (after coverage), added `if provenance: payload["provenance"] = provenance`.

2. `write_isolated_json_report` (file_runner.py ~line 749) — added `provenance` param and passes it through to `_build_isolated_json_payload`.

3. `run_isolated_pytest_units` (file_runner.py ~line 2779) — added `provenance: dict[str, Any] | None = None` param; threaded to all three final-results.json `write_isolated_json_report` calls:
   - ~line 2810: no-tests-collected early exit
   - ~line 2920: resume / nothing-to-do branch
   - ~line 3824: normal completion branch

   Call sites left at `None` (default):
   - ~line 963 (`write_isolated_report` helper) — only reached for JUnit format (not JSON), not the user-facing results.json path; provenance not needed.

4. `cli/test_cmd.py` ~line 548 — `run_isolated_pytest_units(...)` call now passes `provenance=run_provenance`.

### FIX 2 — Guard against KeyError on empty provenance dict

`cli/test_cmd.py` ~line 400: changed `run_provenance["framework"]["version"]` to safe access:
```python
fw = run_provenance.get("framework") or {}
fw_version = fw.get("version") or "?"
```

### FIX 3 — Remove dead guard in merge.py

`core/merge.py` ~line 296: removed `if payload is not None:` guard (unconditionally true since `postprocess_jsonl_to_unified` now always returns a dict). Added a 4-line comment explaining: an empty JSONL now returns a zero-count payload (no findings lost), so the "LOST" warning below is correctly bypassed. Behavior change is intentional and correct.

### FIX 4 — Integration tests for isolated writer path

Added to `tests/test_provenance_wiring.py`:
- `test_build_isolated_json_payload_includes_provenance` — asserts payload contains provenance block
- `test_build_isolated_json_payload_omits_provenance_when_none` — asserts provenance absent when None
- `test_write_isolated_json_report_includes_provenance` — drives full write to tmp file, asserts JSON contains provenance
- `test_write_isolated_json_report_omits_provenance_when_none` — asserts absence when not supplied

Updated `tests/test_cli.py`: added `provenance: object = None` to all 10 `fake_run` mock signatures (replace_all=True on the matching signature tail).

## Test output

```
collected 177 items
tests/test_provenance_wiring.py ........
tests/test_provenance.py ........
tests/test_cli.py ...............................
tests/test_merge_sharding.py ....................
tests/test_file_runner.py ..............................................
................................................................
177 passed in 1.25s
```

## Gates

- `ruff format --check`: 5 files already formatted (OK)
- `ruff check`: All checks passed (OK)
- `mypy --strict` on source files + test_provenance_wiring.py: Success, no issues
- `mypy --strict tests/test_cli.py`: 43 errors (all pre-existing, verified by stash/check/pop)
