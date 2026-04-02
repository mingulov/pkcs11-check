# Audit 29: CKR Compliance

**Date:** 2026-04-01
**OASIS specs referenced:** `function_return_values.md`, mechanism-specific error tables
**Files audited:** All 30 files in `testcases/ckr/`, `_ckr_spec.py`, `_ctypes_raw.py`

## Findings

### Quality Issues

- [FIXED] (in iteration 01) Hardcoded hex CKR values in `_ctypes_raw.py`, `test_ckr_raw_state.py`, `test_ckr_raw_multipart.py` — all replaced with symbolic constants.

### Coverage Status

CKR testing is comprehensive: 30 test files covering encrypt, decrypt, sign, verify, digest, keygen, wrap, derive, object, session, slot/token, random, dual-function, KEM, and v3.0/v3.2 raw operations. The `_ckr_spec.py` file provides specification data for expected return codes.

### Coverage Gaps

- [GAP] Error priority ordering — spec defines that certain errors take precedence (e.g., CKR_SESSION_HANDLE_INVALID before CKR_ARGUMENTS_BAD). No test explicitly verifies priority when multiple error conditions exist simultaneously.
- [GAP] CKR code exhaustiveness — no systematic check that ALL 105 CKR codes from types_std.py are exercised somewhere in the test suite. Some rare codes (CKR_EXCEEDED_MAX_ITERATIONS, CKR_FIPS_SELF_TEST_FAILED) may never be triggered.
- [GAP] v3.2 new CKR codes — verify any new return codes added in v3.2 (e.g., for KEM, authenticated wrap) have test coverage.

## Statistics

- Issues found: 0 new fixed, 3 gaps documented
