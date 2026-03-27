# Master Test Quality and Coverage Plan

**Date:** 2026-03-26
**Status:** Draft

## Problem Statement

pkcs11-check has ~75K tests across 209 files covering 104 PKCS#11 functions, but has systematic quality and coverage gaps that undermine trust in results. The test suite needs:

1. **Infrastructure hardening** — partially-wired compliance system with per-test leakage, unused markers, no PKCS#11-level coverage tracking
2. **Test correctness** — xfail/skip misuse, inconsistent patterns, mechanism name drift
3. **Functional test gaps** — 17 functions with CKR-only coverage (no roundtrip)
4. **Mechanism/CKR expansion** — 7 CKR codes untested, legacy symmetric ciphers uncovered

## Methodology

This plan follows the principle: **fix existing tests first, then expand coverage.** Each phase produces independently verifiable results.

## Phase 1: Test Correctness and Infrastructure Hardening

### 1.1 Fix compliance.note() system

**Problem:** `compliance.note()` is actively used (65+ call sites across test files) and
`compliance_report.py` can serialize notes to JSON. However, `clear_notes()` is never
called between tests, so notes from one test leak into subsequent tests' reports. The
system is partially wired but has a per-test leakage bug and is not integrated into
the standard pytest output hooks.

**Fix:**
- Wire `clear_notes()` into `pytest_runtest_teardown` hook in `plugin.py` to prevent leakage
- Include per-test compliance notes in the unified JSON report output (add `compliance_notes` field per test unit)
- Add compliance notes to the console summary (truncated if >10)
- Add a meta-test verifying the hook integration and per-test isolation

**Files:** `plugin.py`, `core/file_runner.py`, `compliance.py`, `tests/test_compliance_report.py`

### 1.2 Activate or remove `needs_mechanism` marker

**Problem:** The `needs_mechanism` marker is defined in `markers.py`, checked in `plugin.py`, but zero test files use it. ~650 manual `has_mechanism()` calls across 103 files do the same thing imperatively with inconsistent skip messages.

**Fix (recommended):** Convert to a decorator helper that replaces the verbose pattern:

```python
# Before (~650 occurrences across 103 files):
def test_something(self, p11_raw_session):
    rs = p11_raw_session
    if not rs.has_mechanism("AES_GCM"):
        pytest.skip("AES_GCM not supported")

# After:
@needs_mechanism("AES_GCM")
def test_something(self, p11_raw_session):
    rs = p11_raw_session
```

Implementation: Create `needs_mechanism()` decorator in `testcases/conftest.py` that wraps the `has_mechanism()` check. Migrate high-value test files first (sign, encrypt, digest). Leave the marker definition intact for collection-level filtering.

**Files:** `testcases/conftest.py`, `markers.py` (no change needed), 103 test files (gradual migration)

### 1.3 Add PKCS#11 function coverage tracking

**Problem:** Python code coverage (`coverage.py`) tracks which Python lines execute, not which C functions are invoked through ctypes. We cannot answer "what percentage of the PKCS#11 API surface did this test run exercise against module X?"

**Fix:** Add a lightweight call counter to `RawPKCS11._call()`. Since all 104
dynamic methods route through the single `_call(name, *args)` dispatch point,
a single line suffices:

```python
class RawPKCS11:
    def __init__(self, ...):
        self._call_log: dict[str, int] = defaultdict(int)
        ...

    def _call(self, name: str, *args: Any) -> int:
        self._call_log[name] += 1  # one line added
        func = self._funcs.get(name)
        ...
```

**Note:** The raw/ module was recently cleaned up (int() removal, pack.py split,
API renames). Changes to `api.py` should be made against the current state.

- Aggregate per-test in a pytest fixture (store on `p11_raw_session`)
- Include in JSON report: `{"pkcs11_functions_called": {"C_Encrypt": 12, "C_EncryptInit": 12, ...}}`
- Add summary to console output: "PKCS#11 functions exercised: 67/104 (64%)"
- Gate behind `--p11-track-coverage` flag (opt-in, small overhead)

**Files:** `raw/api.py`, `fixtures.py`, `core/file_runner.py`, `plugin.py`

### 1.4 Standardize mechanism skip messages

**Problem:** ~650 `has_mechanism()` calls produce inconsistent skip messages:
- `"AES_ECB not supported"`
- `"CKM_AES_ECB not supported"`
- `"CKM_AES_ECB not supported by module"`

**Fix:** Create a helper in `testcases/conftest.py`:

```python
def skip_unless_mechanism(rs: RawSession, name: str) -> None:
    if not rs.has_mechanism(name):
        pytest.skip(f"{name} not supported")
```

Migrate incrementally. The `@needs_mechanism` decorator (1.2) provides the standard pattern for new tests.

### 1.5 Audit and fix xfail/skip misuse

**Problem:** ~284 `pytest.xfail()` calls across 64 files. Most cover known module bugs (correct usage), but a small number cover missing capabilities that should be `pytest.skip()`. xfails for capability gaps mask when a module adds support.

**Fix:**
- Grep all xfail calls with reason strings
- Categorize: (a) known module bug → keep xfail, (b) missing capability → convert to skip, (c) unclear → flag for review
- For (a), include the module name and issue/CVE in the reason string
- Add a meta-test that validates all xfail reasons match expected patterns

**Files:** 30+ test files (gradual), `tests/` (new meta-test)

### 1.6 Secure PIN passing in subprocess tests (LOW priority)

**Problem:** `_subprocess_preamble.py` embeds the PIN as a literal string in generated
scripts. While `subprocess.run([sys.executable, "-c", script])` does NOT expose the
script content via `ps` (unlike shell commands), the PIN is visible in core dumps.
However, the PIN is already passed via `--p11-pin` or `P11TEST_PIN` env var which are
equally visible. This is a marginal security improvement for a test tool.

**Fix (if desired):** Write PIN to a temp file with `os.open(path, flags=0o600)`, pass
the file path as an argument, read and delete in the subprocess. Update
`subprocess_session_preamble()` to accept a pin_file parameter.

**Files:** `testcases/_subprocess_preamble.py`, `testcases/_raw_subprocess.py`

## Phase 2: CKR Return Code Coverage Expansion

### 2.1 Add 7 missing CKR code tests

These CKR codes are defined in `types_std.py` and the OASIS spec but have no test coverage:

| CKR Code | How to Test | Difficulty |
|----------|-------------|------------|
| `CKR_PIN_TOO_WEAK` | `C_InitPIN` with a 1-byte PIN (module may enforce minimum) | LOW |
| `CKR_PUBLIC_KEY_INVALID` | Import malformed public key, then sign | MEDIUM |
| `CKR_PENDING` | Async operation check (if module supports async) | LOW (presence check) |
| `CKR_FIPS_SELF_TEST_FAILED` | Presence check — module must return if FIPS self-test fails | LOW (presence check) |
| `CKR_LIBRARY_LOAD_FAILED` | Presence check — cannot easily trigger | LOW (presence check) |
| `CKR_OPERATION_NOT_VALIDATED` | `C_VerifySignatureFinal` without validation (v3.1+) | MEDIUM |
| `CKR_TOKEN_NOT_INITIALIZED` | `C_InitPIN` on uninitialized token | LOW |

**Note:** `CKR_AEAD_DECRYPT_FAILED` is already tested in `_ckr_spec.py` and `test_acvp_aes.py`.

**Implementation:** Add CkrExpectation entries in `_ckr_spec.py` for testable ones. For untestable-in-practice ones (CKR_LIBRARY_LOAD_FAILED, CKR_FIPS_SELF_TEST_FAILED, CKR_PENDING), add documented `testable=False` entries.

**Files:** `testcases/ckr/_ckr_spec.py`, `testcases/ckr/test_ckr_*` (new tests for the 3 testable ones)

### 2.2 Audit CKR spec completeness against OASIS spec

The `_ckr_spec.py` contains 862 CkrExpectation entries. Verify completeness against the OASIS spec:

1. Extract all function+error combinations from OASIS `function_return_values.md`
2. Cross-reference against all CkrExpectation entries in `_ckr_spec.py`
3. Report gaps with function name, error code, and expected context

**Files:** `testcases/ckr/_ckr_spec.py` (audit), `docs/` (gap report)

## Phase 3: Functional Test Expansion

### 3.1 VerifySignature API (v3.0+ loaded, v3.1 spec) — 4 functions

**Problem:** `C_VerifySignatureInit/Update/Final` have CKR error expectations but no positive-path roundtrip test. This API differs from `C_VerifyInit` — it accepts the signature at initialization time, not final time.

**Version handling note:** The codebase only distinguishes v2.40, v3.0, and v3.2.
`interface_version` returns `"3.0"` for both 3.0 and 3.1 modules (they share the
same function set). The VerifySignature functions (metadata indices 94-97) load as
part of the v3.0+ block. There is no `@requires_v31` marker. Tests should gate on
`"C_VerifySignatureInit" in raw.available_function_names()` rather than version strings.

**New test file:** `test_verify_signature.py`

Tests:
1. Roundtrip: sign with `C_SignInit` → verify with `C_VerifySignatureInit` + `C_VerifySignature` (single-shot)
2. Roundtrip: sign multipart → verify with `C_VerifySignatureInit` + `C_VerifySignatureUpdate` + `C_VerifySignatureFinal` (multipart)
3. Wrong signature returns CKR_SIGNATURE_INVALID
4. Wrong key returns CKR_KEY_HANDLE_INVALID or CKR_SIGNATURE_INVALID
5. Gate: skip if `C_VerifySignatureInit` not in `available_function_names()`

**Requires:** A module implementing these functions. No known module currently does — tests will likely skip until implementations appear.

**Files:** `testcases/test_verify_signature.py` (new)

### 3.2 Message-based functions (v3.0) — 20 functions

**Problem:** All 20 message-based functions (C_MessageEncryptInit through
C_MessageVerifyFinal) lack positive-path tests. ~6 have CKR error tests in
`test_ckr_v30_raw.py` and `_ckr_spec.py` has expectations for all 20, but none have
functional roundtrip tests. No current module implements these.

**Approach:** Write the test infrastructure now so it's ready when modules add support:

1. Create `testcases/test_message_crypto.py` with `@requires_v30` marker
2. Each test checks mechanism availability (e.g., `CKM_AES_CBC` for message encrypt) and skips if unavailable
3. Tests cover the full lifecycle: `MessageEncryptInit` → `EncryptMessage`/`EncryptMessageBegin`+`EncryptMessageNext` → `MessageEncryptFinal`
4. All 4 domains: encrypt, decrypt, sign, verify
5. Cross-verification: encrypt with message API, decrypt with standard API (and vice versa)

**Note:** These tests will skip on all current modules but will catch implementations as they appear. The CKR error tests already exist.

**Files:** `testcases/test_message_crypto.py` (new)

### 3.3 C_GetSessionValidationFlags (v3.0+ loaded, v3.1 spec) — 1 function

**New test:** Query validation flags on a session, verify they're a non-empty flags
bitmask. Gate: skip if `C_GetSessionValidationFlags` not in `available_function_names()`.

**Files:** `testcases/test_v30_session.py` (extend)

### 3.4 Async function lifecycle (v3.0+) — 3 functions

**Problem:** `C_AsyncComplete`, `C_AsyncGetID`, `C_AsyncJoin` have only presence/CKR
tests. `test_remaining_gaps.py` already has basic presence checks.

**Approach:** Write a test that starts an async operation (if supported), polls with
`C_AsyncGetID`, and completes with `C_AsyncJoin`. Gate on
`available_function_names()`. If no module supports async, tests skip.

**Files:** `testcases/test_async.py` (new)

## Phase 4: Mechanism Coverage Expansion

### 4.1 High-priority mechanism tests

These mechanisms are commonly supported but lack dedicated functional tests.
`test_remaining_gaps.py` has basic presence/stub tests for some (SHAKE, KMAC,
ML_DSA_EXTERNAL_MU) but no roundtrip verification:

| Mechanism | Category | Test Type | Effort |
|-----------|----------|-----------|--------|
| `CKM_SHAKE_128`, `CKM_SHAKE_256` | Digest | Roundtrip + cross-verify vs hashlib | LOW |
| `CKM_SHA512_224`, `CKM_SHA512_256` | Digest | Roundtrip + cross-verify vs hashlib | LOW |
| `CKM_AES_KEY_WRAP_KWP` | Wrap | Wrap/unwrap roundtrip | LOW |
| `CKM_KMAC_128`, `CKM_KMAC_256` | MAC (v3.2) | Roundtrip (if module supports) | MEDIUM |
| `CKM_ML_DSA_EXTERNAL_MU` | PQC Sign (v3.2) | Sign/verify roundtrip | MEDIUM |

### 4.2 Legacy symmetric ciphers (LOW priority)

These are obsolete/deprecated but defined in PKCS#11:

| Mechanism | Category | Notes |
|-----------|----------|-------|
| `CKM_RC2_ECB/CBC/CBC_PAD` | Symmetric | Deprecated, NIST disallowed |
| `CKM_RC4` | Stream cipher | Deprecated, multiple CVEs |
| `CKM_RC5_ECB/CBC` | Symmetric | Rarely implemented |
| `CKM_CAST3_*`, `CKM_CAST128_*` | Symmetric | Legacy |
| `CKM_IDEA_*` | Symmetric | Legacy |

**Recommendation:** Do NOT write tests for these. They are security-obsolete and no modern module should support them. If a module advertises them, the mechanism info + CKR error tests already provide basic coverage.

### 4.3 Vendor mechanism coverage via pkcs11-proxy

The `pkcs11-proxy` project has descriptions of vendor-specific mechanisms. For modules that advertise vendor mechanisms (e.g., Kryoptic, OpenCryptoki IBM), add availability-check tests that:
1. Enumerate vendor mechanisms via `C_GetMechanismList`
2. Query info via `C_GetMechanismInfo`
3. Log mechanism names and flags for human review
4. No functional tests (vendor mechanisms are non-standard)

**Files:** `testcases/test_vendor_extensions.py` (extend), `testcases/test_surface_audit.py` (extend)

## Phase 5: Test Validation Framework

### 5.1 Per-test PKCS#11 function coverage report

After Phase 1.3 (call tracking), add a pytest hook that emits a report:

```
=== PKCS#11 Function Coverage ===
Total functions in spec: 104
Functions called: 78 (75%)
Uncalled: C_DecryptMessage, C_DecryptMessageBegin, ...
By category:
  Session management: 11/11 (100%)
  Encryption: 8/9 (89%)
  ...
```

### 5.2 Mechanism coverage report

Extend the surface audit to produce per-mechanism coverage:

```
=== Mechanism Coverage ===
Advertised by module: 164
Tested (functional): 65 (40%)
Tested (CKR error only): 89 (54%)
Untested: 10 (6%)
```

### 5.3 Baseline comparison workflow

Create a reproducible workflow:
1. Run full suite, capture JSON report
2. Diff against a known-good baseline (committed JSON fixture per module)
3. Flag regressions (previously-passing tests now failing/crashing)
4. Flag improvements (previously-skipped tests now passing)

**Files:** `scripts/compare-results.py` (new), `tests/data/baselines/` (new)

## Dependencies

- **raw/ module cleanup** (Phase 1 and 2 in `2026-03-26-raw-module-cleanup-design.md`
  and `2026-03-26-raw-module-polish-design.md`) is complete. Changes to `api.py`,
  `recipes.py`, `pack.py` etc. should be made against the current `dev` branch state.

## Execution Order

| Phase | Dependencies | Estimated Effort |
|-------|-------------|-----------------|
| 1.1-1.2 | None | Small-Medium (2 days — decorator + 103-file gradual migration) |
| 1.3-1.4 | None | Medium (2 days) |
| 1.5 | None | Medium (2 days) |
| 1.6 | None | Small (0.5 day) |
| 2.1-2.2 | None | Small (1 day) |
| 3.1-3.4 | 1.1-1.3 done | Medium (3 days — tests will mostly skip) |
| 4.1-4.3 | 1.2-1.4 done | Medium (3 days) |
| 5.1-5.3 | 1.3 done | Medium-Large (3 days — 12 module baselines) |

**Total estimated: ~17 days of focused work.** Add ~3-5 days for multi-module
Docker validation if full coverage across all 12 targets is required.

## Success Criteria

After all phases:
1. `compliance.note()` system functional and wired into reports
2. `@needs_mechanism` decorator available and used in new tests
3. PKCS#11 function coverage report shows >80% of v2.40+v3.0 functions exercised
4. 95+ of 105 CKR codes covered (up from 90)
5. All 4 v3.1 VerifySignature functions have positive-path tests
6. Message-based test infrastructure ready for future modules
7. Mechanism coverage report shows >50% of advertised mechanisms functionally tested
8. Baseline comparison workflow operational
9. All existing tests still pass (no regressions from infrastructure changes)
