# PKCS#11 Session Reuse Speed Design

## Goal

Reduce wolfPKCS11 and other slow-bootstrap provider runtime without removing tests, weakening crash detection, or adding provider-specific baselines.

## Root Cause

Current artifacts show several high-vector files spend almost all wall time in pytest setup, not in the test body. The common path is `p11_raw_session`, which opens a fresh session, logs in, then logs out and closes for every parametrized vector. That is correct for lifecycle and destructive tests, but wasteful for vector/object-import tests where the property under test is independent per object or operation.

For wolfPKCS11 master, the worst files are setup-dominated:

- `test_cctv_ed25519.py`: 914 vectors, all skipped after fixture setup, 857s setup and 0.24s call time.
- `test_cctv_mldsa.py`: 449 vectors, 424s setup and 0.49s call time.
- `x509/test_limbo_import.py`: 663 vectors, 548s setup and 0.37s call time.
- `x509/test_limbo_stress.py`: 1009 vectors, 842s setup and 0.50s call time.

Other providers show the same structural pattern with lower setup cost. The bug is not that these tests exist; it is that many high-count tests pay fresh-session cost when they are not testing fresh-session behavior.

## Design

Use two provider-neutral optimizations.

First, files whose whole purpose requires one or more mechanisms should declare `REQUIRED_MECHANISMS`. The isolated runner already reads the manifest and records a synthetic file-skip with counted skipped tests when a required mechanism is absent. This avoids opening sessions just to skip every parameter in the test body. In-body `has_mechanism` checks remain as defensive guards for non-isolated pytest use and stale/missing manifests.

Second, audited high-count vector/import files should use the existing `p11_module_session` fixture instead of `p11_raw_session`. This keeps file-level subprocess crash survival intact while avoiding repeated `C_OpenSession`/`C_Login`/`C_Logout`/`C_CloseSession`. The fixture health-checks each handout, reopens if the session is damaged, resets per-test call counters, and recovers from stale active operations via existing recipe logic.

This is an explicit file-level audit, not an automatic rewrite. Do not convert tests that exercise login, PIN, session lifecycle, reinitialization, wrong-PIN destructive behavior, token-locking behavior, or intentional raw subprocess crash scripts.

The JSON report path must preserve synthetic file-skip details even when the final report is rebuilt from pytest-reportlog JSONL records. Otherwise the console can show a file-skip while `results.json` incorrectly treats the unit as an uncounted pass.

## Initial Scope

Apply the first optimization to:

- `src/pkcs11_check/testcases/test_cctv_ed25519.py` with `REQUIRED_MECHANISMS = ["EDDSA"]`.
- `src/pkcs11_check/testcases/test_cctv_mldsa.py` with `REQUIRED_MECHANISMS = ["ML_DSA", "ML_DSA_KEY_PAIR_GEN"]`.

Apply the second optimization to:

- `src/pkcs11_check/testcases/test_cctv_ed25519.py`.
- `src/pkcs11_check/testcases/test_cctv_mldsa.py`.
- `src/pkcs11_check/testcases/test_hash_ml_dsa.py`.
- `src/pkcs11_check/testcases/test_aes_modes.py`.
- `src/pkcs11_check/testcases/test_des.py`.
- `src/pkcs11_check/testcases/test_dsa_complete.py`.
- `src/pkcs11_check/testcases/test_kem.py`.
- `src/pkcs11_check/testcases/x509/test_limbo_import.py`.
- `src/pkcs11_check/testcases/x509/test_limbo_stress.py`.

These files create per-test temporary objects or keys with `CKA_TOKEN=False` and destroy handles in `finally` blocks, or skip at the operation-mechanism layer while preserving per-test capability coverage. They do not test session lifecycle.

## Safety Invariants

- Missing mechanism remains a skip, not a hidden pass, and appears in JSON reports.
- File-skip counts survive JSONL merge/rewrite paths in `results.json` and `quality.json`.
- Provider crashes remain findings because file/test subprocess isolation is unchanged.
- Type-A and self-contradiction failures remain failures.
- No provider identity checks, allowlists, baselines, xfails, or crash suppressions are introduced.
- `p11_raw_session` remains available and unchanged for tests that require fresh sessions.
- The old in-body capability checks remain where they document the local operation precondition.

## Verification Loop

Use TDD for report/selection behavior first, then convert the scoped test files.

Run local gates:

- `uv run python -m pytest tests/test_test_selection.py tests/test_file_runner.py tests/test_raw_fixtures.py tests/test_operation_active_recovery.py -q`
- `uv run python -m pytest tests/test_python_source_syntax.py tests/test_security_subprocess_regressions.py tests/test_subprocess_result_policy.py -q`
- `uv run ruff check src/ tests/`

Run Docker/provider checks in loops:

- First targeted wolfPKCS11 master checks for the four hot files.
- Compare `results.json` counts and `report.jsonl` setup/call split against the previous artifact baseline.
- If the largest remaining wolfPKCS11 master time is still setup-dominated in other audited-safe files, repeat with the next safe conversion.
- Run at least one non-wolf provider targeted check for the same files to confirm no coverage loss or provider-specific breakage.

## Non-Goals

- Do not drop, disable, or xfail tests for speed.
- Do not add provider-specific behavior.
- Do not convert destructive/security/lifecycle suites automatically.
- Do not update release statistics documentation as part of this optimization.
