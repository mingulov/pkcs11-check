# p11test Gap Analysis

Repo-grounded snapshot as of 2026-03-19.

This document is intentionally stricter than `docs/master-plan.md`. It focuses on what is still missing, where the code and docs drift apart, and which edge cases are still under-specified or under-tested.

## Current Snapshot

- The project already has a large product suite: `src/p11test/testcases/` currently contains 105 top-level test files.
- Strict collection currently sees 29,644 testcase items in this environment.
- The `python-pkcs11` fork now supports PKCS#11 v3.0/v3.1/v3.2 negotiation, `interface_version`, and `get_interface_list()`.
- The package metadata already claims the project name `p11test`.
- The project is strong on breadth, but the main remaining risk is execution-model completeness and productization polish.

## What Is Already Strong

- Broad test scope: classic crypto, PQC, Wycheproof, interop, CVE regressions, stress, stateful tests, and mechanism auditing.
- Good local build ergonomics via `local-builds/`.
- A serious `python-pkcs11` fork instead of thin wrappers around v2.40-only APIs.
- Clear separation between product tests (`src/p11test/testcases/`) and meta-tests (`tests/`).
- Good direction on markers, categories, and module-matrix style reporting.

## Confirmed Gaps

### 1. Core Execution Path Is Still Incomplete

The project promise is "CLI-first PKCS#11 test suite with segfault survival, interface forcing, and pytest plugin." Interface forcing is now real. Segfault survival is not yet integrated into the real runner path.

### Confirmed issues

- `src/p11test/cli/test_cmd.py` still calls `pytest.main(...)` in-process.
- `src/p11test/plugin.py` no longer loads the PKCS#11 module during collection; it now uses a preflight manifest. Collection safety is materially better than before.
- `src/p11test/fixtures.py` still loads modules and opens sessions directly in normal pytest execution.
- `src/p11test/core/file_runner.py` provides practical per-file subprocess isolation and resume support, but plain `--isolation none` remains in-process.
- `src/p11test/core/isolation.py` exists, uses `spawn`, and has tests, but it is not what `p11test test` actually uses for product execution today.

### Why this matters

- A bad PKCS#11 library is less likely to kill collection now, because capability probing moved to a preflight subprocess.
- A crash in fixture setup or teardown can still take down the whole process.
- The implementation does not yet fully match the product claim or the isolation-oriented specs in `docs/superpowers/`.

### Recommended direction

- Keep collection-safe preflight probing.
- Decide on the real default isolation contract for the test command.
- Extend the current per-file path toward per-test isolation for crash-prone units.

### 2. CLI, Config, and Actual Behavior Still Drift

There is a visible gap between the CLI surface, the config model, and what the code actually does.

### Confirmed issues

- `--sessions` exists in `src/p11test/cli/test_cmd.py` but is not used.
- `--timeout` exists in `src/p11test/cli/test_cmd.py` but is not used.
- isolated modes now emit real aggregated JSON/JUnit reports and expose `p11test state` for inspection.
- `--output json` in non-isolated mode still relies on `pytest-json-report`, so output semantics differ by runner path.
- `P11TestConfig` contains `timeout_operation`, `timeout_test`, `max_sessions`, `skip_unsupported`, `log_level`, and `output`, but only part of that model is wired through the fixtures and CLI path.
- `pyproject.toml` sets `testpaths = ["tests"]`, so plain `pytest` runs only meta-tests, not the product suite.

### Why this matters

- Users can set knobs that do nothing.
- Automation consumers cannot rely on a stable machine-readable report format yet.
- There is a risk of documentation promising more control than the runner actually exposes.

### Recommended direction

- Either wire every advertised option end-to-end or remove/defer it.
- Decide whether isolated and non-isolated JSON output should converge on one schema.
- Add explicit docs for the difference between `pytest tests/`, `pytest src/p11test/testcases/`, and `p11test test`.

### 3. Marker Execution Policy Is Still Partial

The marker registration situation is much better than before, but marker-driven execution policy is still only partially implemented.

### Confirmed issues

- `thread_safe` is now registered and handled by the plugin.
- strict-marker collection is no longer the active blocker it was before.
- `subprocess_per_test` is now wired into `--isolation auto`, and crashing files are now promoted to per-test isolation through the adaptive policy file.
- `--isolation auto` now also escalates a crashing file to per-test isolation immediately inside the same run.
- plain `subprocess` now keeps files on the file-isolated path in `--isolation auto`.
- Marker registration is still ahead of marker-driven execution in a few places.

### Why this matters

- Marker registration is part of the public plugin contract.
- The remaining drift is more about execution semantics than collection-time correctness.

### Recommended direction

- Keep marker registration fully generated or fully audited.
- Decide whether plain `subprocess` should remain "file-first but promotable" or become "never promote past file."

### 4. Error-Handling Discipline Is Not Yet Consistent

The project rules are strong, but the codebase does not yet fully follow them.

### Confirmed issues

- `src/p11test/fixtures.py` no longer contains the broad logout cleanup catch.
- Many testcase files still catch broad `PKCS11Error` rather than named expected CKR-specific exception classes.
- The repository already has `src/p11test/testcases/_error_tuples.py`, which means the intended direction is clear, but the migration is incomplete.

### Why this matters

- Broad catches can hide real module defects and produce false passes or misleading skips.
- Cleanup code is often where spec violations get silently ignored.

### Recommended direction

- Treat generic `PKCS11Error` catches as debt and burn them down systematically.
- Document the acceptable exceptions per operation pattern and reuse shared tuples/helpers.

### 5. Interface Support Exists, but Interface Validation Is Still Shallower Than It Could Be

The v3.x loader criticism is no longer valid. That part has advanced. The remaining gap is test depth, especially negative-path coverage.

### Confirmed positives

- `src/p11test/core/loader.py` accepts `auto`, `2.40`, `3.0`, `3.1`, and `3.2`.
- `src/p11test/cli/info_cmd.py` prints negotiated interface information and available interfaces when exposed by the library.
- `src/p11test/testcases/test_interface.py` and `src/p11test/testcases/test_interface_negotiation.py` cover positive-path negotiation and basic capability checks.

### Confirmed gaps

- Negative `C_GetInterface` and `C_GetInterfaceList` behavior is not covered as explicitly as in OpenSC's `p11test_case_interface.c`.
- `src/p11test/testcases/test_interface_negotiation.py` checks `hasattr(p11_module, "get_interface_list")`, but the current wrapper exposes that method on `p11_module.lib`, not on `P11Module` itself.
- Explicit version-forcing behavior is not yet deeply regression-tested across mixed-process and repeated-load scenarios.

### Recommended direction

- Add a dedicated interface-negotiation regression file for:
  - invalid interface name
  - invalid flags
  - unsupported explicit version
  - repeated load with different forced versions in one process
  - modules that expose `C_GetInterfaceList` but have inconsistent entries

### 6. Reporting and Baseline Regression Workflow Are Still Thin

OpenSC's `p11test` is narrower, but it has a more concrete JSON regression harness today.

### Confirmed issues

- `--isolation auto|file|test` now has aggregated JSON/JUnit result artifacts.
- There is no stable baseline comparison flow equivalent to "run suite -> emit structured results -> diff against known-good artifact" in the main CLI path.
- There is no built-in "capability snapshot" output that could be archived alongside module results.

### Nice additions here

- JSON result schema versioning with per-test outcome, duration, marker set, mechanism requirements, crash/timeout status, and module metadata.
- Capability snapshot command that records slot info, mechanism list, interface list, token flags, and library identity.
- Golden baseline files for smoke/full profiles per module.

### 7. Packaging and Distribution Readiness Are Still Early

The package name may be available, but the release surface is not production-ready yet.

### Confirmed issues

- `README.md` is empty.
- CI exists now, but it is still relatively shallow.
- `pyproject.toml` has minimal project metadata; it lacks URLs, classifiers, and packaging polish expected for a public release.
- There is no documented release flow for publishing wheels or sdists.
- There is no install-time smoke test documented for users who are not working from this exact repo layout.

### Recommended direction

- Write a real README first.
- Add CI for meta-tests, lint, type check, strict-marker collection, and at least one smoke token.
- Add project URLs, supported-platform statement, and release steps.

### 8. Documentation Drift Exists

The repo has strong planning docs, but some of them read more "desired state" than "verified current state."

### Confirmed issues

- `docs/master-plan.md` marks many infrastructure items as complete, but the live code still has execution-path gaps.
- The top-level README is empty, so the user-facing truth currently lives in scattered docs and code.
- There is no single "what works today / what is partial / what is planned" document.

### Recommended direction

- Keep `docs/master-plan.md` as an aspirational execution plan.
- Add a simpler "current status" document for users and contributors.
- Periodically reconcile docs against quick repo validation checks.

### 9. CI and Validation Gates Are Missing

Current quality depends heavily on local discipline.

### Confirmed issues

- GitHub Actions workflows are present and cover lint, typecheck, meta-tests, strict markers, and a SoftHSM2 smoke job.
- The remaining gap is breadth: crash-prone backends and isolated report paths are not all gated in CI yet.

### Minimum suggested gates

- `ruff check src/ tests/`
- `mypy src/`
- `pytest tests/`
- `pytest --strict-markers src/p11test/testcases --collect-only -q`
- one CLI smoke run against a known-good software token

## Edge Cases Still Worth Adding or Tightening

These are the cases most likely to expose runner or wrapper weaknesses rather than ordinary mechanism bugs.

### A. Collection and Startup Edge Cases

- Module loads successfully, but `get_slots(token_present=True)` returns an empty list.
- Slot index exists in config but not in the loaded module.
- Module exports v3.x symbols but returns malformed interface metadata.
- Module crashes during mechanism enumeration, not during a test body.
- Library can be loaded once per process but refuses a second forced interface selection.

### B. Session and Login State Edge Cases

- Token that needs no user PIN at all.
- Protected authentication path token where CLI PIN should not be used.
- SO-only tokens or unusual login state transitions.
- Multi-session login and logout order where one session invalidates another.
- Token-level login semantics under worker concurrency.

### C. Parallelism and Resource-Isolation Edge Cases

- Multiple workers using the same token label namespace and colliding on object labels.
- Parallel tests sharing token-global login state.
- Session exhaustion under xdist workers versus within one process.
- Same test run mixing safe per-thread operations and destructive token-global tests.

### D. Interface and Version-Forcing Edge Cases

- Explicit `3.2` request on a `3.0`-only module.
- Explicit `3.1` request on a `2.40`-only module.
- Auto-negotiation after a previous explicit `2.40` load in the same process.
- Mixed v2.40/v3.x attribute behavior across reload cycles.

### E. Reporting and UX Edge Cases

- Crash/timeout outcome preserved in machine-readable output.
- Distinguish setup failure from test-call failure from teardown failure.
- Stable exit-code contract for CI consumers.
- Partial-run resume or rerun support after a crash-heavy campaign.

### F. Install and Packaging Edge Cases

- Wheel install without editable local submodule layout.
- Running `p11test info` and `p11test test` from a clean virtualenv.
- Version mismatch between published `p11test` and published `python-pkcs11`.

## Nice Additions Beyond the Current Plan

These are not the highest-risk gaps, but they would make the project materially better.

### 1. User-Facing Additions

- `p11test doctor` command for environment checks, module load sanity, slot listing, and dependency hints.
- `p11test capabilities` command that writes a JSON capability snapshot.
- `p11test matrix` command that aggregates multiple run results into one report.
- `p11test explain <test-id>` output that shows marker set, mechanism requirements, and skip logic.

### 2. Engineering Additions

- JSON schema for test results and module capability snapshots.
- Dedicated regression tests for the CLI, not just plugin internals.
- Generated docs for marker taxonomy and category definitions.
- A single validation script that mirrors CI locally.

### 3. Ecosystem Additions

- Stable baseline comparisons against OpenSC `p11test` where overlap exists.
- Optional import of external vector/corpus sets beyond Wycheproof.
- More explicit support policy for hardware HSMs vs software tokens.

## Suggested Priority Order

### P0: Correctness and Trust

1. Decide and implement the real default crash-isolation execution path.
2. Finish marker-driven isolation for plain `subprocess`.
3. Burn down broad `PKCS11Error` catches in testcase files.
4. Add stronger validation gates for local-helper and crash-prone providers.

### P1: Product Surface

1. Wire or remove dead CLI/config options.
2. Implement real JSON reporting.
3. Write a real README and current-status document.
4. Add CI with at least one smoke module.

### P2: Depth and Parity

1. Strengthen interface-negotiation negative tests.
2. Add stable baseline artifact comparison.
3. Improve worker/resource-isolation design for future parallelism.

## Bottom Line

`p11test` is already a serious framework, not a toy. The current weakness is not lack of test breadth or lack of PKCS#11 v3.x support. The weakness is that the execution backbone, user-facing packaging, and validation gates still lag behind the ambition of the suite.

That is good news in one sense: the project does not need a new direction. It needs consolidation, enforcement, and productization.
