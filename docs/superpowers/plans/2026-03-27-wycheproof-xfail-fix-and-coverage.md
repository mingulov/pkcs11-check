# Wycheproof xfail→fail Fix & Coverage Improvements — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Use **Sonnet 4.6** for implementation tasks, **Opus 4.6** for review tasks.

**Goal:** Replace blanket `pytest.xfail()` with `pytest.fail()` in all Wycheproof tests for valid vectors (exposing hidden module bugs), add subprocess call_log capture for coverage tracking, and add mechanism detail tracking to GCM/CCM/EdDSA/CTR packers.

**Architecture:** Component 1 (xfail fix) is a mechanical pattern replacement across 16 Wycheproof test files — separate output-validation assertions from CKR-rejection catches. Component 2 (subprocess coverage) extends `_subprocess_preamble.py` and `_raw_subprocess.py` to dump call_log to temp files. Component 3 (detail tracking) adds `sub_mechanisms` to 4 mechanism packers.

**Tech Stack:** Python 3.11+, pytest, pkcs11_check.raw, pkcs11_check.testcases.wycheproof

**Spec:** `docs/superpowers/specs/2026-03-27-wycheproof-xfail-fix-and-coverage-improvements.md`

---

## Task 1: Fix Wycheproof xfail Pattern — Signature/Verify Files (8 files)

**Goal:** Replace `pytest.xfail()` with `pytest.fail()` for valid vectors in signature verification Wycheproof tests, and move output-validation assertions outside the try/except block.

**Files:**
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ed25519.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa_sign.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_dsa.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_hmac.py`

- [ ] **Step 1:** For each file, apply this transformation pattern:

**Before (broken):**
```python
    except AssertionError:
        if result == "valid":
            pytest.xfail(f"Valid sig {vec_id} rejected")
        return
```

**After (correct):**
```python
    except AssertionError as exc:
        if result == "valid":
            pytest.fail(f"Valid vector {vec_id} rejected: {exc}")
        return  # acceptable: module rejected invalid vector
```

Key changes per file:
- `test_wycheproof_rsa.py:175` — change `pytest.xfail` → `pytest.fail`
- `test_wycheproof_rsa_pss.py:210` — change `pytest.xfail` → `pytest.fail`
- `test_wycheproof_ecdsa.py:257` — change `pytest.xfail` → `pytest.fail`; also fix line 205 `except Exception:` → `except AssertionError:` (bare Exception is dangerous)
- `test_wycheproof_ed25519.py:172` — change `pytest.xfail` → `pytest.fail`
- `test_wycheproof_mldsa.py:128` — change `pytest.xfail` → `pytest.fail`
- `test_wycheproof_mldsa_sign.py:130` — import-phase xfail → `pytest.fail`; line 139 `except (AssertionError, Exception):` → `except AssertionError:` (narrow the catch)
- `test_wycheproof_dsa.py` — check if any xfail exists (it may only have regular failure logic)
- `test_wycheproof_hmac.py:176,185` — change both xfails to fails

- [ ] **Step 2:** Lint all 8 files
```bash
uv run ruff check src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_ed25519.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa_sign.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_hmac.py
```

- [ ] **Step 3:** Commit
```bash
git commit -m 'fix: replace xfail with fail for valid vectors in signature Wycheproof tests'
```

---

## Task 2: Fix Wycheproof xfail Pattern — Encryption/Decrypt/Derive Files (8 files)

**Goal:** Same pattern replacement for encryption, decryption, key derivation, and KEM Wycheproof tests.

**Files:**
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_chacha.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_oaep.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_decrypt.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_x25519.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_hkdf.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mlkem.py`

- [ ] **Step 1:** Apply the xfail→fail transformation to each file.

Critical variations:
- `test_wycheproof_aes.py` — **7 xfail sites** (CMAC:104, KW:177, KWP:251+257, CCM:328, GMAC:387, XTS:448). For sites where output is validated inside the try block (`assert ct == expected`), move the output assertion OUTSIDE the except so wrong output is a hard failure, not caught.
- `test_wycheproof_chacha.py:106` — catches `(AssertionError, AttributeError, TypeError)` — keep `AttributeError`/`TypeError` in the catch but change to `pytest.fail`
- `test_wycheproof_rsa_oaep.py:205` — straightforward
- `test_wycheproof_rsa_decrypt.py:125` — straightforward
- `test_wycheproof_ecdh.py:190` — already has partial mismatch guard (`if "mismatch" in exc_msg: raise`). Change the xfail to fail. The mismatch guard can stay as-is since it re-raises.
- `test_wycheproof_x25519.py:149` — catches `(AssertionError, TypeError)`. Change xfail → fail.
- `test_wycheproof_hkdf.py:153` — catches `(AssertionError, TypeError, NotImplementedError)`. Change xfail → fail.
- `test_wycheproof_mlkem.py:136,171` — catches `(AssertionError, Exception)`. **CRITICAL:** Narrow to `AssertionError` only — bare `Exception` hides Python bugs.

- [ ] **Step 2:** Lint all 8 files
```bash
uv run ruff check src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_chacha.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_oaep.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_decrypt.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_x25519.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_hkdf.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_mlkem.py
```

- [ ] **Step 3:** Commit
```bash
git commit -m 'fix: replace xfail with fail for valid vectors in encrypt/derive Wycheproof tests'
```

---

## Task 3: Fix Wycheproof xfail Pattern — Main + PBES2/PBKDF2 (3 files)

**Goal:** Fix the remaining 3 files including the main test_wycheproof.py (5 xfail sites) and the unconditional PBES2 xfails.

**Files:**
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_pbes2.py`
- Modify: `src/pkcs11_check/testcases/wycheproof/test_wycheproof_pbkdf2.py`

- [ ] **Step 1:** Fix `test_wycheproof.py` (5 xfail sites)

This file handles "acceptable" results: `if result == "valid" or result == "acceptable":`. Keep this logic — both valid and acceptable vectors should fail if rejected.

Change each `pytest.xfail()` to `pytest.fail()` at lines 129, 163, 229, 244, 448.

- [ ] **Step 2:** Fix `test_wycheproof_pbes2.py` (2 unconditional xfail sites)

Lines 148 and 163 xfail WITHOUT checking `if result == "valid"`. Add the result check:

```python
# Line 148 area — key derivation:
except AssertionError as exc:
    if result == "valid":
        pytest.fail(f"PBES2 key derivation failed for valid vector {vec_id}: {exc}")
    return  # acceptable: module rejected invalid vector

# Line 163 area — decrypt:
except AssertionError as exc:
    destroy_quietly(rs.raw, rs.sh, key)
    if result == "valid":
        pytest.fail(f"PBES2 decrypt failed for valid vector {vec_id}: {exc}")
    return
```

- [ ] **Step 3:** Fix `test_wycheproof_pbkdf2.py` — straightforward xfail → fail at line 155

- [ ] **Step 4:** Lint all 3 files
```bash
uv run ruff check src/pkcs11_check/testcases/wycheproof/test_wycheproof.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_pbes2.py src/pkcs11_check/testcases/wycheproof/test_wycheproof_pbkdf2.py
```

- [ ] **Step 5:** Commit
```bash
git commit -m 'fix: replace xfail with fail in main Wycheproof, PBES2, PBKDF2 tests'
```

---

## Task 4: Add sub_mechanisms to GCM/CCM/EdDSA/CTR Packers

**Goal:** Enrich mechanism detail tracking for high-value mechanisms.

**Files:**
- Modify: `src/pkcs11_check/raw/pack_mechanisms.py:54-100` (mech_gcm, mech_ccm)
- Modify: `src/pkcs11_check/raw/pack_mechanisms.py:203-209` (mech_ctr)
- Modify: `src/pkcs11_check/raw/pack_mechanisms.py:241-251` (mech_eddsa)

- [ ] **Step 1:** Add `sub_mechanisms` to `mech_gcm` (line 78)

Change:
```python
    return _mech_struct(mechanism_type, params, "mech_gcm", ka)
```
To:
```python
    return _mech_struct(mechanism_type, params, "mech_gcm", ka,
                        sub_mechanisms={"tagBits": tag_bits})
```

- [ ] **Step 2:** Add `sub_mechanisms` to `mech_ccm` (line 100)

Change:
```python
    return _mech_struct(mechanism_type, params, "mech_ccm", ka)
```
To:
```python
    return _mech_struct(mechanism_type, params, "mech_ccm", ka,
                        sub_mechanisms={"macLen": mac_len, "nonceLen": len(nonce)})
```

- [ ] **Step 3:** Add `sub_mechanisms` to `mech_ctr` (line 209)

Change:
```python
    return _mech_struct(mechanism_type, params, "mech_ctr")
```
To:
```python
    return _mech_struct(mechanism_type, params, "mech_ctr",
                        sub_mechanisms={"counterBits": bits})
```

- [ ] **Step 4:** Add `sub_mechanisms` to `mech_eddsa` (line 251)

Change:
```python
    return _mech_struct(mechanism_type, params, "mech_eddsa", ka)
```
To:
```python
    return _mech_struct(mechanism_type, params, "mech_eddsa", ka,
                        sub_mechanisms={"phFlag": int(params.phFlag)})
```

- [ ] **Step 5:** Lint and type-check
```bash
uv run ruff check src/pkcs11_check/raw/pack_mechanisms.py
uv run mypy src/pkcs11_check/raw/pack_mechanisms.py
```

- [ ] **Step 6:** Commit
```bash
git commit -m 'feat: add sub_mechanisms detail tracking to GCM/CCM/CTR/EdDSA packers'
```

---

## Task 5: Subprocess Coverage — Extend Preamble and Raw Runner

**Goal:** Capture call_log from subprocess tests and make it available for coverage merging.

**Files:**
- Modify: `src/pkcs11_check/testcases/_subprocess_preamble.py:72-76`
- Modify: `src/pkcs11_check/testcases/_raw_subprocess.py:32-45`

- [ ] **Step 1:** Extend `_subprocess_preamble.py` cleanup to dump coverage

At line 72-74, the `cleanup()` function is generated as a string. Change the template:

```python
    f"def cleanup():\n"
    f"    import json as _json, os as _os\n"
    f"    _cov_path = _os.environ.get('_P11CHECK_SUBPROCESS_COVERAGE')\n"
    f"    if _cov_path:\n"
    f"        try:\n"
    f"            _json.dump({{\n"
    f"                'call_log': raw.call_log,\n"
    f"                'mechanism_counts': {{str(k): v for k, v in raw.mechanism_counts.items()}},\n"
    f"            }}, open(_cov_path, 'w'))\n"
    f"        except Exception:\n"
    f"            pass\n"
    f"    close_session_quietly(raw, sh)\n"
    f"    raw.C_Finalize(None)\n"
    f"\n"
```

- [ ] **Step 2:** Extend `_raw_subprocess.py` `run_raw_script()` to pass and read coverage

Add coverage file handling around the subprocess.run call:

```python
import json
import tempfile

def run_raw_script(
    boilerplate: str,
    script_body: str,
    cleanup: str = "",
    timeout: int = 15,
) -> tuple[int, str, str]:
    """Run a ctypes PKCS#11 script in a subprocess."""
    full_script = boilerplate + textwrap.dedent(script_body)
    if cleanup:
        full_script += textwrap.dedent(cleanup)

    # Create temp file for subprocess coverage data
    cov_fd, cov_path = tempfile.mkstemp(suffix=".json", prefix="p11cov_")
    os.close(cov_fd)
    env = {**os.environ, "_P11CHECK_SUBPROCESS_COVERAGE": cov_path}

    result = subprocess.run(
        [sys.executable, "-c", full_script],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )

    # Read subprocess coverage (may not exist if subprocess crashed)
    subprocess_coverage = None
    try:
        with open(cov_path) as f:
            subprocess_coverage = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    finally:
        try:
            os.unlink(cov_path)
        except OSError:
            pass

    return result.returncode, result.stdout.strip(), result.stderr.strip()
```

Note: The `subprocess_coverage` data is read but not yet used. Task 6 wires it into the plugin.

- [ ] **Step 3:** Lint
```bash
uv run ruff check src/pkcs11_check/testcases/_subprocess_preamble.py src/pkcs11_check/testcases/_raw_subprocess.py
```

- [ ] **Step 4:** Commit
```bash
git commit -m 'feat: subprocess tests dump call_log to temp file for coverage capture'
```

---

## Task 6: Wire Subprocess Coverage into Plugin

**Goal:** Make subprocess coverage data accessible to plugin.py for merging into cumulative counters.

**Files:**
- Modify: `src/pkcs11_check/testcases/_raw_subprocess.py` (store coverage on thread-local or module global)
- Modify: `src/pkcs11_check/plugin.py` (read subprocess coverage at teardown)

- [ ] **Step 1:** Store subprocess coverage in module-level accumulator

In `_raw_subprocess.py`, add a module-level accumulator:

```python
from collections import Counter

_subprocess_call_counts: Counter[str] = Counter()
_subprocess_mechanism_counts: Counter[str] = Counter()

def get_subprocess_coverage() -> tuple[Counter[str], Counter[str]]:
    """Return accumulated subprocess coverage and clear it."""
    func = Counter(_subprocess_call_counts)
    mech = Counter(_subprocess_mechanism_counts)
    _subprocess_call_counts.clear()
    _subprocess_mechanism_counts.clear()
    return func, mech
```

In `run_raw_script()`, after reading subprocess_coverage:
```python
    if subprocess_coverage:
        _subprocess_call_counts.update(subprocess_coverage.get("call_log", {}))
        for k, v in subprocess_coverage.get("mechanism_counts", {}).items():
            _subprocess_mechanism_counts[k] += v
```

- [ ] **Step 2:** In plugin.py teardown, drain subprocess coverage

In `pytest_runtest_teardown`, after the existing funcargs loop (around line 380):

```python
    # Drain subprocess coverage (from _raw_subprocess and _subprocess_preamble tests)
    try:
        from pkcs11_check.testcases._raw_subprocess import get_subprocess_coverage
        sub_func, sub_mech = get_subprocess_coverage()
        if sub_func:
            cumulative.update(sub_func.keys())
            session.config.stash[_CUMULATIVE_FUNCTION_COUNTS].update(sub_func)
        if sub_mech:
            # Mechanism counts are string-keyed from subprocess
            session.config.stash[_CUMULATIVE_MECHANISM_COUNTS].update(
                {int(k): v for k, v in sub_mech.items() if k.isdigit()}
            )
    except ImportError:
        pass
```

- [ ] **Step 3:** Also wire `_subprocess_preamble.py` consumers

The `_subprocess_preamble.py` consumers (ckr tests) use their own `_run()` helpers, not `run_raw_script()`. They need the same env var and file-reading logic. Add a shared helper:

In `_subprocess_preamble.py`, add:
```python
import json
import os
import tempfile

def run_with_coverage(
    script: str, timeout: int = 15
) -> tuple[int, str, str, dict[str, Any] | None]:
    """Run subprocess script with coverage capture. Returns (rc, stdout, stderr, coverage)."""
    import subprocess
    import sys

    cov_fd, cov_path = tempfile.mkstemp(suffix=".json", prefix="p11cov_")
    os.close(cov_fd)
    env = {**os.environ, "_P11CHECK_SUBPROCESS_COVERAGE": cov_path}

    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=timeout, env=env,
    )

    coverage = None
    try:
        with open(cov_path) as f:
            coverage = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    finally:
        try:
            os.unlink(cov_path)
        except OSError:
            pass

    return result.returncode, result.stdout.strip(), result.stderr.strip(), coverage
```

Also add module-level accumulators (same pattern as `_raw_subprocess.py`):
```python
from collections import Counter

_subprocess_call_counts: Counter[str] = Counter()
_subprocess_mechanism_counts: Counter[str] = Counter()

def get_preamble_subprocess_coverage() -> tuple[Counter[str], Counter[str]]:
    func = Counter(_subprocess_call_counts)
    mech = Counter(_subprocess_mechanism_counts)
    _subprocess_call_counts.clear()
    _subprocess_mechanism_counts.clear()
    return func, mech
```

- [ ] **Step 4:** In plugin.py, also drain preamble subprocess coverage:
```python
    try:
        from pkcs11_check.testcases._subprocess_preamble import get_preamble_subprocess_coverage
        sub_func, sub_mech = get_preamble_subprocess_coverage()
        if sub_func:
            cumulative.update(sub_func.keys())
            session.config.stash[_CUMULATIVE_FUNCTION_COUNTS].update(sub_func)
    except ImportError:
        pass
```

- [ ] **Step 5:** Lint and type-check
```bash
uv run ruff check src/pkcs11_check/testcases/_raw_subprocess.py src/pkcs11_check/testcases/_subprocess_preamble.py src/pkcs11_check/plugin.py
```

- [ ] **Step 6:** Commit
```bash
git commit -m 'feat: wire subprocess coverage into plugin cumulative counters'
```

---

## Task 7: Verification

**Goal:** Verify all 3 components work correctly.

- [ ] **Step 1:** Run meta-tests
```bash
uv run python -m pytest tests/ -x -q
```
Expected: all pass (except pre-existing pkcs11f.h failure).

- [ ] **Step 2:** Run SoftHSM2 smoke to verify detail tracking
```bash
bash docker/test.sh softhsm2 -- src/pkcs11_check/testcases/test_aead.py src/pkcs11_check/testcases/test_encrypt.py
```
Check coverage.json:
```python
python3 -c "
import json
d = json.load(open('artifacts/softhsm2/coverage.json'))
detail = d['mechanism_coverage'].get('invoked_detail', [])
for d in detail:
    if 'GCM' in d or 'CCM' in d or 'CTR' in d:
        print(d)
"
```
Expected: `CKM_AES_GCM[tagBits=128]` in invoked_detail.

- [ ] **Step 3:** Run Kryoptic-main to verify xfails become failures
```bash
bash docker/test.sh kryoptic-main -- src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py
```
Expected: valid ECDH vectors now FAIL (not xfail). Failure count increases, xfail count decreases.

- [ ] **Step 4:** Check subprocess coverage improvement
```bash
bash docker/test.sh softhsm2 -- src/pkcs11_check/testcases/ckr/test_ckr_raw_args_bad.py
```
Check if previously-uncalled functions now appear in coverage.

- [ ] **Step 5:** Commit verification notes
```bash
git commit --allow-empty -m 'chore: verified xfail→fail, detail tracking, subprocess coverage'
```
