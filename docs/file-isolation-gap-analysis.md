# File Isolation Gap Analysis

Date: 2026-03-19

## Scope Re-Checked

This review is about the current `p11test test --isolation file` implementation:

- CLI wiring in `src/p11test/cli/test_cmd.py`
- per-file runner in `src/p11test/core/file_runner.py`
- subprocess base helper in `src/p11test/core/isolation.py`
- current pytest plugin behavior in `src/p11test/plugin.py`
- collection-safe capability probing in `src/p11test/core/preflight.py`
- local BouncyHSM smoke validation with the patched native shim
- local helper validation through `local-builds/test.sh`

Checks run during this review:

- `uv run pytest tests/test_cli.py tests/test_file_runner.py tests/test_isolation.py tests/test_plugin.py tests/test_preflight.py tests/test_loader.py -q`
- `uv run ruff check src/p11test/cli/test_cmd.py src/p11test/core/file_runner.py src/p11test/core/isolation.py src/p11test/core/preflight.py src/p11test/plugin.py src/p11test/fixtures.py tests/test_cli.py tests/test_file_runner.py tests/test_isolation.py tests/test_plugin.py tests/test_preflight.py tests/test_loader.py`
- `uv run mypy src/p11test/core/file_runner.py src/p11test/cli/test_cmd.py src/p11test/core/isolation.py src/p11test/core/preflight.py src/p11test/plugin.py src/p11test/fixtures.py`
- local BouncyHSM stop-and-resume smoke:
  - first run stopped at a real failing file
  - second run resumed from that file and continued to the next one
- local shell helper smoke:
  - `P11TEST_ISOLATION=file bash local-builds/test.sh ...` now reaches the same runner path
  - caller-supplied transport env such as `BOUNCY_HSM_CFG_STRING` is preserved
- direct pytest smoke:
  - `uv run pytest ... test_interface.py::TestInterfaceV30::test_v30_interface_negotiated ...`
    passed against local BouncyHSM
  - BouncyHSM server logs confirmed a separate `python -m p11test.core.preflight` helper
    loaded the module before the pytest process ran the test

## What Works Now

The current solution is useful and real. It is not just a draft.

- `--isolation file` runs each requested file or nodeid in a fresh `python -m pytest` subprocess.
- `--stop-on-failure` stops at the first failing, crashing, or timing-out unit and leaves a resumable state file.
- `--resume` skips only units already marked `passed` or `empty`.
- rerunning a failed unit replaces the old state entry instead of appending duplicates.
- resume now rejects mismatched state files via a fingerprint of the requested units and pytest arguments.
- the subprocess helper now consistently uses `spawn`, which is the safer default for PKCS#11 isolation.
- the state fingerprint now also covers relevant environment plus test/module file metadata.
- file isolation now uses env-only PIN propagation to child pytest processes.
- the local helper can opt into file isolation and stateful resume instead of always bypassing the CLI.
- dynamic version/mechanism skips no longer load the PKCS#11 module during pytest collection.
- direct `pytest` runs now use the same subprocess preflight path when they need dynamic skip data.

The BouncyHSM smoke confirmed the intended workflow:

1. `test_ckr_codes.py` passed.
2. `test_ckr_decrypt.py` failed on a real module behavior mismatch.
3. `--stop-on-failure` stopped at that file and saved state.
4. `--resume` reran `test_ckr_decrypt.py` and then continued to `test_ckr_digest.py`.

That is already useful for unstable modules and for long regression sweeps.

## Confirmed Gaps

### P0: This is still per-file isolation, not per-test isolation

The most important remaining architectural gap is now granularity, not collection safety.

- one crash during collection inside a file-sized child still loses that whole file
- one crash in an early test still prevents the rest of that file from running
- marker-driven `subprocess_per_test` is still metadata only

The collection-safe preflight manifest fixed the old parent-process collection hazard, but the runner is still a per-file tactical layer rather than the final per-test isolation design.

### P1: Resume protection is stronger, but still not complete

The state fingerprint covers only:

- requested units
- pytest arguments
- relevant environment
- test file metadata
- module binary metadata

It does not cover:

- plugin or fixture code changes
- non-file inputs such as token database contents or daemon state

So a user can still resume into a technically stale continuation after changing fixture/plugin code or after changing external token state without changing the module binary or test files.

### P1: Reporting is intentionally narrow

`--isolation file` currently supports only `--output rich`.

Missing pieces:

- aggregated JUnit XML
- aggregated JSON output
- a machine-readable summary for CI
- an easy way to see only failed/crashed/timed-out units from the saved state

For local debugging this is fine. For CI and dashboards it is not enough yet.

### P1: Timeout behavior is coarse

The outer file timeout is currently `max(per_test_timeout * 10, 300)`.

That is pragmatic but blunt:

- a tiny file still waits up to 300 seconds
- a large file with many slow tests may need more than `10x`
- the multiplier is not tied to the actual number of tests in the file

This is acceptable as a safety valve, but it is not a principled timeout model.

### P1: File isolation is not the same as per-test isolation

The new mode isolates files or explicit nodeids, not individual collected tests inside a file.

Consequences:

- one crash during collection loses the whole file
- one crash in an early test means the rest of that file does not run
- very large files are still relatively coarse failure domains

This is still a good regression mode, but it is not the end state described by the long-term isolation plans.

### P1: Marker-driven subprocess behavior is still not wired

`src/p11test/markers.py` registers `subprocess` and `subprocess_per_test`, but the runner does not interpret them yet.

Right now subprocess behavior is chosen only by CLI mode, not by test metadata.

### P2: `--sessions` remains ignored in file mode

The CLI warns correctly, but the feature is still missing:

- no file-level parallelism
- no worker isolation strategy
- no relationship defined between `--sessions`, xdist workers, and shared token state

That is the correct conservative choice today, but it remains an open design gap.

### P2: Local BouncyHSM startup is still manual and a bit fragile

The local BouncyHSM smoke worked, but only with the LiteDb-backed server mode and only when the process was started from the published server directory so it could load `appsettings.Docker.json`.

Current limitations:

- provider setup prints instructions but does not launch the server
- provider setup does not create a slot automatically
- the in-memory default mode is still not the stable local path
- the helper now respects caller-supplied `BOUNCY_HSM_CFG_STRING`, but the default printed instructions still describe the standard 8765/5011 path

## Edge Cases Worth Calling Out

- Starting a fresh run without `--resume` overwrites the old state file immediately.
- A resumed run intentionally reruns failed units, so state files should not be treated as immutable history.
- The parent CLI still accepts `--pin`, but file mode now keeps it in environment propagation instead of child command-line arguments.
- `discover_pytest_units()` accepts explicit nodeids and whole directories, but the default unit order is just filesystem order, not historical-failure order or duration-aware scheduling.

## Recommended Next Steps

### Short Term

1. Add a small helper to print saved-state summaries without opening the JSON manually.
2. Decide whether the local shell helper should accept a broader set of pytest-style flags in isolation mode.
3. Add a lightweight marker-aware mode for `@subprocess` and `@subprocess_per_test`.
4. Document the collection-safe preflight manifest path more explicitly for direct `pytest` users.

### Medium Term

1. Add aggregated JUnit/JSON reporting for file isolation runs.
2. Add a small `p11test state` or `p11test resume-status` helper to inspect saved state files.
3. Refine timeout calculation to account for file size or collected test count.
4. Add an option to resume only failed/crashed units from a saved state without repeating already passed files in the target list.

### Long Term

1. Move from per-file to true per-test subprocess isolation for marked crash-prone tests or for the whole product suite.
2. Define a real worker-isolation model before enabling concurrent file execution.
3. Decide whether preflight data should be reused across workers through a shared manifest cache.

## Bottom Line

The new file isolation mode is worth keeping. It solves a real operational problem now:

- long runs can continue after a broken file
- the user can stop and resume from the failure point
- unstable modules no longer require a single all-or-nothing pytest invocation

But it is still a tactical layer, not the final segfault-survival design. The biggest missing pieces are per-test isolation, richer reporting, and a real worker model.
