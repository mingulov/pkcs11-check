# PKCS#11 Session Reuse Speed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Reduce wolfPKCS11 master Docker runtime by avoiding unnecessary per-vector session bootstrap in audited-safe high-count tests.

**Architecture:** Reuse existing provider-neutral mechanisms: `REQUIRED_MECHANISMS` for collection-time whole-file capability skips, and `p11_module_session` for audited vector/object-import files. Keep file/test subprocess isolation unchanged so provider crashes still become findings.

**Tech Stack:** Python 3.13, pytest, pkcs11-check isolated file runner, `uv run`, Docker provider test wrapper.

---

### Task 1: Guard Capability File Skip Behavior

**Files:**
- Modify: `tests/test_file_runner.py`
- Modify if needed: `src/pkcs11_check/core/file_runner.py`

- [x] **Step 1: Write the failing test**

Add a test proving a file with multiple required mechanisms is skipped before subprocess execution when any mechanism is missing, and that all collected nodeids are counted as skipped.

```python
def test_file_skip_for_any_missing_required_mechanism_counts_collected_tests(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    test_file = tmp_path / "test_demo.py"
    test_file.write_text(
        'REQUIRED_MECHANISMS = ["ML_DSA", "ML_DSA_KEY_PAIR_GEN"]\n'
        "def test_a(): pass\n"
        "def test_b(): pass\n"
    )
    state_file = tmp_path / "state.json"
    report_path = tmp_path / "results.json"

    calls: list[list[str]] = []

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        calls.append(cmd)
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_load_available_mechanisms", lambda _args: {"ML_DSA"})
    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    monkeypatch.setattr(
        file_runner_mod,
        "collect_pytest_nodeids",
        lambda targets, pytest_args, *, env=None: [
            f"{test_file}::test_a",
            f"{test_file}::test_b",
        ],
    )

    exit_code = run_isolated_pytest_units(
        [str(test_file)],
        ["--p11-module", "/tmp/module.so", "--p11-manifest", str(tmp_path / "manifest.json")],
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=IsolatedReportConfig("json", report_path),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    report = json.loads(report_path.read_text())
    unit = report["units"][0]

    assert exit_code == 0
    assert calls == []
    assert unit["file_skip"] is True
    assert unit["counts"]["skipped"] == 2
    assert unit["skip_reasons"] == {"ML_DSA_KEY_PAIR_GEN not supported by module": 2}
```

- [x] **Step 2: Run test to verify it fails only if current behavior is insufficient**

Run:

```bash
uv run python -m pytest tests/test_file_runner.py::test_file_skip_for_any_missing_required_mechanism_counts_collected_tests -q
```

Expected: PASS if existing runner behavior already covers this. If it fails, failure must show subprocess execution or incorrect skipped counts.

- [x] **Step 3: Keep or minimally adjust runner behavior**

If the test fails, adjust only `src/pkcs11_check/core/file_runner.py` around the existing file-skip branch so any missing mechanism prevents subprocess execution and `_synthetic_file_skip_detail()` is used for counted skipped tests.

- [x] **Step 4: Run focused file-runner tests**

Run:

```bash
uv run python -m pytest tests/test_file_runner.py::test_file_skip_for_missing_mechanism tests/test_file_runner.py::test_file_skip_counts_collected_tests_as_skipped tests/test_file_runner.py::test_file_skip_for_any_missing_required_mechanism_counts_collected_tests -q
```

Expected: all selected tests pass.

- [x] **Step 5: Guard JSONL report merge for file-skips**

Add a regression test where one file is mechanism-skipped before subprocess execution and a later unit writes pytest-reportlog records. The final `results.json` must preserve the file-skip detail and skipped counts after JSONL merge.

If it fails, update the supplemental detail merge helper so `file_skip` details are copied through alongside crash/timeout synthetic details.

### Task 2: Add Mechanism Declarations to CCTV Files

**Files:**
- Modify: `src/pkcs11_check/testcases/test_cctv_ed25519.py`
- Modify: `src/pkcs11_check/testcases/test_cctv_mldsa.py`
- Test: `tests/test_test_selection.py`

- [x] **Step 1: Write failing metadata tests**

Add tests proving the target files expose static required mechanisms.

```python
def test_cctv_ed25519_declares_required_mechanism() -> None:
    assert extract_required_mechanisms("src/pkcs11_check/testcases/test_cctv_ed25519.py") == ["EDDSA"]


def test_cctv_mldsa_declares_required_mechanisms() -> None:
    assert extract_required_mechanisms("src/pkcs11_check/testcases/test_cctv_mldsa.py") == [
        "ML_DSA",
        "ML_DSA_KEY_PAIR_GEN",
    ]
```

- [x] **Step 2: Run tests to verify RED**

Run:

```bash
uv run python -m pytest tests/test_test_selection.py::test_cctv_ed25519_declares_required_mechanism tests/test_test_selection.py::test_cctv_mldsa_declares_required_mechanisms -q
```

Expected: FAIL with `None` or missing declarations.

- [x] **Step 3: Add declarations**

Add near the top-level `pytestmark` block:

```python
REQUIRED_MECHANISMS = ["EDDSA"]
```

and:

```python
REQUIRED_MECHANISMS = ["ML_DSA", "ML_DSA_KEY_PAIR_GEN"]
```

- [x] **Step 4: Run tests to verify GREEN**

Run:

```bash
uv run python -m pytest tests/test_test_selection.py::test_cctv_ed25519_declares_required_mechanism tests/test_test_selection.py::test_cctv_mldsa_declares_required_mechanisms -q
```

Expected: both pass.

### Task 3: Convert Audited High-Count Files to Module Sessions

**Files:**
- Modify: `src/pkcs11_check/testcases/test_cctv_ed25519.py`
- Modify: `src/pkcs11_check/testcases/test_cctv_mldsa.py`
- Modify: `src/pkcs11_check/testcases/test_hash_ml_dsa.py`
- Modify: `src/pkcs11_check/testcases/test_aes_modes.py`
- Modify: `src/pkcs11_check/testcases/test_des.py`
- Modify: `src/pkcs11_check/testcases/test_dsa_complete.py`
- Modify: `src/pkcs11_check/testcases/test_kem.py`
- Modify: `src/pkcs11_check/testcases/x509/test_limbo_import.py`
- Modify: `src/pkcs11_check/testcases/x509/test_limbo_stress.py`
- Test: `tests/test_session_reuse_metadata.py`

- [x] **Step 1: Write metadata tests for fixture usage**

Create `tests/test_session_reuse_metadata.py`:

```python
from __future__ import annotations

from pathlib import Path


def _text(path: str) -> str:
    return Path(path).read_text()


def test_hot_vector_files_use_module_session() -> None:
    for path in [
        "src/pkcs11_check/testcases/test_cctv_ed25519.py",
        "src/pkcs11_check/testcases/test_cctv_mldsa.py",
        "src/pkcs11_check/testcases/test_hash_ml_dsa.py",
        "src/pkcs11_check/testcases/test_aes_modes.py",
        "src/pkcs11_check/testcases/test_des.py",
        "src/pkcs11_check/testcases/test_dsa_complete.py",
        "src/pkcs11_check/testcases/test_kem.py",
        "src/pkcs11_check/testcases/x509/test_limbo_import.py",
        "src/pkcs11_check/testcases/x509/test_limbo_stress.py",
    ]:
        text = _text(path)
        assert "p11_module_session" in text, path
        assert "p11_raw_session" not in text, path
```

- [x] **Step 2: Run test to verify RED**

Run:

```bash
uv run python -m pytest tests/test_session_reuse_metadata.py -q
```

Expected: FAIL because the scoped files still use `p11_raw_session`.

- [x] **Step 3: Change fixture names only**

For each scoped test function, change the fixture parameter from `p11_raw_session` to `p11_module_session`, and change local assignment to `rs = p11_module_session`. Do not change classification logic, CKR lists, object creation, or cleanup paths.

- [x] **Step 4: Run metadata and syntax tests**

Run:

```bash
uv run python -m pytest tests/test_session_reuse_metadata.py tests/test_python_source_syntax.py -q
```

Expected: pass.

### Task 4: Local Regression Gate

**Files:**
- No new files.

- [x] **Step 1: Run focused regression tests**

Run:

```bash
uv run python -m pytest tests/test_test_selection.py tests/test_file_runner.py tests/test_raw_fixtures.py tests/test_operation_active_recovery.py tests/test_session_reuse_metadata.py -q
```

Expected: all pass.

- [x] **Step 2: Run documented fast gate**

Run:

```bash
uv run python -m pytest tests/test_python_source_syntax.py tests/test_security_subprocess_regressions.py tests/test_subprocess_result_policy.py -q
```

Expected: all pass.

- [x] **Step 3: Run lint**

Run:

```bash
uv run ruff check src/ tests/
```

Expected: no lint errors.

### Task 5: Docker Provider Verification Loop

**Files:**
- No source files unless the loop reveals another audited-safe hotspot.

- [x] **Step 1: Run targeted wolfPKCS11 master hot files**

Run:

```bash
bash docker/test.sh wolfpkcs11-master -- src/pkcs11_check/testcases/test_cctv_ed25519.py src/pkcs11_check/testcases/test_cctv_mldsa.py src/pkcs11_check/testcases/x509/test_limbo_import.py src/pkcs11_check/testcases/x509/test_limbo_stress.py
```

Expected: counts remain semantically valid, crashes remain crashes, and setup time for converted files drops sharply compared with prior artifacts.

- [x] **Step 2: Compare timing split**

Use `results.json` and `report.jsonl` from the new artifact directory to compare duration/counts with previous artifacts. Confirm `test_cctv_ed25519.py` is file-skipped when EDDSA is missing, not per-vector skipped after fixture setup.

- [x] **Step 3: Run at least one non-wolf provider targeted check**

Run the same four files on a provider with different behavior, preferably `softhsm2` or `opencryptoki`.

Expected: no new harness errors, no missing collection, and no unintended skip/drop of supported tests.

- [x] **Step 4: Repeat hotspot analysis**

Inspect the new wolfPKCS11 master artifact. If a remaining top setup-dominated file is an audited-safe vector/import suite, add a new TDD task for that file and repeat the conversion/test loop. If the remaining time is test-call dominated or destructive/security-lifecycle dominated, document it and stop optimizing that class.

- [x] **Step 5: Round-two audited file**

For `test_hash_ml_dsa.py`, use the same session-reuse guard and fixture-name-only conversion. Keep per-mechanism skips in the test body so providers with partial HASH-ML-DSA support still run supported variants instead of file-skipping the whole module.

Verify at least one provider where the file is fully or partially runnable and one provider where the file-skip path applies. If wolfPKCS11 reports pre-existing HASH-ML-DSA operation failures, compare against older artifacts before treating them as regressions from this change.

- [x] **Step 6: Round-three audited files**

For `test_aes_modes.py`, `test_des.py`, `test_dsa_complete.py`, and `test_kem.py`, use the same session-reuse guard and fixture-name-only conversion after auditing that the files do not test session lifecycle and that temporary handles are still cleaned up explicitly.

Verify the wolfPKCS11 targeted slice against older artifacts before treating provider findings as regressions. Do not convert the remaining security, FFI, destructive, or lifecycle-heavy hotspots without a separate design.
