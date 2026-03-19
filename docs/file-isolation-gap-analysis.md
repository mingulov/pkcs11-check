# File Isolation Gap Analysis

Date: 2026-03-19

## Scope Re-Checked

This review is about the current `p11test test --isolation file` implementation:

- CLI wiring in `src/p11test/cli/test_cmd.py`
- per-file runner in `src/p11test/core/file_runner.py`
- subprocess base helper in `src/p11test/core/isolation.py`
- current pytest plugin behavior in `src/p11test/plugin.py`
- local BouncyHSM smoke validation with the patched native shim

Checks run during this review:

- `uv run pytest tests/test_cli.py tests/test_file_runner.py tests/test_isolation.py -q`
- `uv run ruff check src/p11test/cli/test_cmd.py src/p11test/core/file_runner.py src/p11test/core/isolation.py tests/test_cli.py tests/test_file_runner.py tests/test_isolation.py`
- `uv run mypy src/p11test/core/file_runner.py src/p11test/cli/test_cmd.py src/p11test/core/isolation.py`
- local BouncyHSM stop-and-resume smoke:
  - first run stopped at a real failing file
  - second run resumed from that file and continued to the next one

## What Works Now

The current solution is useful and real. It is not just a draft.

- `--isolation file` runs each requested file or nodeid in a fresh `python -m pytest` subprocess.
- `--stop-on-failure` stops at the first failing, crashing, or timing-out unit and leaves a resumable state file.
- `--resume` skips only units already marked `passed` or `empty`.
- rerunning a failed unit replaces the old state entry instead of appending duplicates.
- resume now rejects mismatched state files via a fingerprint of the requested units and pytest arguments.
- the subprocess helper now consistently uses `spawn`, which is the safer default for PKCS#11 isolation.

The BouncyHSM smoke confirmed the intended workflow:

1. `test_ckr_codes.py` passed.
2. `test_ckr_decrypt.py` failed on a real module behavior mismatch.
3. `--stop-on-failure` stopped at that file and saved state.
4. `--resume` reran `test_ckr_decrypt.py` and then continued to `test_ckr_digest.py`.

That is already useful for unstable modules and for long regression sweeps.

## Confirmed Gaps

### P0: This is still not the final crash-survival architecture

The biggest remaining gap is still in `src/p11test/plugin.py`.

- collection still calls `load_module()` in `pytest_collection_modifyitems()`
- interface detection and mechanism detection still happen during collection
- a bad module can still crash a child pytest process during collection

`--isolation file` contains that failure to one file-sized subprocess, which is much better than the old in-process run, but it is not full per-test isolation and it is not a collection-safe parent process design yet.

### P0: `local-builds/test.sh` does not use the new path

`local-builds/test.sh` still runs raw `uv run pytest ...`.

That means the main fast local workflow does not benefit from:

- per-file subprocess restarts
- resume state
- `--stop-on-failure`

Today the new isolation mode is available only through `uv run p11test test ...`.

### P0: Resume protection is good, but still not complete

The state fingerprint covers only:

- requested units
- pytest argument list with `--p11-pin` redacted

It does not cover:

- file contents or mtimes
- module binary changes
- environment changes such as `BOUNCY_HSM_CFG_STRING`
- plugin or fixture code changes

So a user can resume an old run after changing the module or the tests and still get a technically valid but stale continuation.

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

## Edge Cases Worth Calling Out

- Starting a fresh run without `--resume` overwrites the old state file immediately.
- A resumed run intentionally reruns failed units, so state files should not be treated as immutable history.
- The parent CLI still accepts `--pin`, and file mode currently propagates it into child pytest arguments as `--p11-pin`. That is functional, but it is a weaker secrecy story than env-only propagation.
- `discover_pytest_units()` accepts explicit nodeids and whole directories, but the default unit order is just filesystem order, not historical-failure order or duration-aware scheduling.

## Recommended Next Steps

### Short Term

1. Make `local-builds/test.sh` optionally call `uv run p11test test --isolation file` instead of raw pytest.
2. Remove PKCS#11 module loading from collection-time logic in `src/p11test/plugin.py`.
3. Move child PIN propagation to environment variables only in file isolation mode.
4. Document the state file overwrite behavior directly in CLI help text.

### Medium Term

1. Add aggregated JUnit/JSON reporting for file isolation runs.
2. Add a small `p11test state` or `p11test resume-status` helper to inspect saved state files.
3. Refine timeout calculation to account for file size or collected test count.
4. Add an option to resume only failed/crashed units from a saved state without repeating already passed files in the target list.

### Long Term

1. Move from per-file to true per-test subprocess isolation for marked crash-prone tests or for the whole product suite.
2. Make the parent process collection-safe by replacing collection-time probing with a subprocess-generated capability manifest.
3. Define a real worker-isolation model before enabling concurrent file execution.

## Bottom Line

The new file isolation mode is worth keeping. It solves a real operational problem now:

- long runs can continue after a broken file
- the user can stop and resume from the failure point
- unstable modules no longer require a single all-or-nothing pytest invocation

But it is still a tactical layer, not the final segfault-survival design. The biggest missing pieces are collection safety, integration into the main local workflow, and richer reporting.
