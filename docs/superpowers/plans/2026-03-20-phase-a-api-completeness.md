# Phase A: Core API Function Completeness

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add functional (happy-path) tests for every PKCS#11 C_* function that currently lacks them, achieving ~95%+ API function coverage.

**Architecture:** Each task creates or extends a test file with functional tests. All functions already have CKR error-path tests in `testcases/ckr/` — this phase adds the success-path tests. Tests auto-skip when the function is unsupported.

**Tech Stack:** Python 3.11+, pytest, python-pkcs11 fork, uv, ruff, mypy

**Deep gap analysis finding:** All "missing" functions have CKR error-path coverage in `testcases/ckr/`. What's missing is functional/happy-path tests that verify the function works correctly, not just that it returns the right error codes.

---

## Context for Implementers

### Key Files to Read First
- `CLAUDE.md` — project coding rules (CRITICAL: no generic `except PKCS11Error: pass`)
- `src/pkcs11_check/testcases/conftest.py` — shared helpers (has_mechanism, mech_name, etc.)
- `src/pkcs11_check/fixtures.py` — p11_session, p11_module, p11_config fixtures
- `src/pkcs11_check/markers.py` — available markers (@requires_v30, @destructive, etc.)
- `docs/superpowers/plans/2026-03-20-oasis-compliance-roadmap.md` — master roadmap with cross-cutting rules

### OASIS Spec Location
`/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/`

### Test Commands
```bash
# Run only Phase A tests
bash local-builds/test.sh softhsm2 src/pkcs11_check/testcases/test_operation_state.py src/pkcs11_check/testcases/test_sign_recover.py src/pkcs11_check/testcases/test_dual_function.py -v

# Full regression
bash local-builds/test.sh softhsm2
bash local-builds/test.sh kryoptic

# Lint + type check
uv run ruff check src/pkcs11_check/testcases/
uv run mypy src/pkcs11_check/testcases/ --ignore-missing-imports
```

### Cross-Cutting Rules (from master roadmap)
- Document module quirks in `docs/module-issues.md`
- Use `compliance.note()` for spec deviations
- Use `pytest.xfail()` with explanation for known module bugs
- NEVER use generic `except PKCS11Error: pass`
- Use `has_mechanism()` + `pytest.skip()` for mechanism availability
- v3.0+ tests: add `@pytest.mark.requires_v30` or `@pytest.mark.requires_v32`

---

### Task 1: C_GetOperationState / C_SetOperationState

**Files:**
- Create: `src/pkcs11_check/testcases/test_operation_state.py`
- Reference: OASIS spec `session_mgmt_functions.md` (§5.6.5, §5.6.6)
- Existing CKR tests: `src/pkcs11_check/testcases/ckr/test_ckr_state.py`
- Pattern: `src/pkcs11_check/testcases/test_multipart.py` (multi-part operations)

**What to test:**
- Start a multi-part digest (C_DigestInit + C_DigestUpdate), save state, restore, finish
- Start a multi-part encrypt, save state, restore on a different session, finish
- Verify restored operation produces the same result as uninterrupted operation
- Handle CKR_STATE_UNSAVEABLE gracefully (some modules don't support this)
- Handle CKR_SAVED_STATE_INVALID for cross-session restore

- [ ] **Step 1:** Read OASIS spec section §5.6.5 (C_GetOperationState) and §5.6.6 (C_SetOperationState)
- [ ] **Step 2:** Read existing CKR tests at `ckr/test_ckr_state.py` to understand error paths already covered
- [ ] **Step 3:** Write test file with digest state save/restore round-trip
- [ ] **Step 4:** Add encrypt state save/restore test
- [ ] **Step 5:** Add xfail/skip handling for CKR_STATE_UNSAVEABLE
- [ ] **Step 6:** Run tests on SoftHSM2, document any quirks
- [ ] **Step 7:** Run ruff check + commit

---

### Task 2: C_SignRecover / C_VerifyRecover

**Files:**
- Create: `src/pkcs11_check/testcases/test_sign_recover.py`
- Reference: OASIS spec `signing_and_macing_functions.md` (§5.10.5, §5.10.6) and `functions_for_verifying_signatures_and_macs.md` (§5.11.5, §5.11.6)
- Pattern: `src/pkcs11_check/testcases/test_sign.py` (sign/verify pattern)

**What to test:**
- RSA X.509 (raw) sign-recover: data is recoverable from signature
- RSA X.509 verify-recover: extract data from signature
- Round-trip: sign-recover → verify-recover → compare original data
- CKM_RSA_X_509 is the primary mechanism for recovery operations
- Skip cleanly if CKM_RSA_X_509 not supported

- [ ] **Step 1:** Read OASIS spec for C_SignRecover and C_VerifyRecover
- [ ] **Step 2:** Check if CKM_RSA_X_509 is in python-pkcs11 Mechanism enum (add if missing)
- [ ] **Step 3:** Write sign-recover round-trip test with RSA_X_509
- [ ] **Step 4:** Write verify-recover test
- [ ] **Step 5:** Add mechanism availability skip
- [ ] **Step 6:** Run tests, commit

---

### Task 3: C_LoginUser (v3.0+)

**Files:**
- Create: `src/pkcs11_check/testcases/test_v30_session.py`
- Reference: OASIS spec `session_mgmt_functions.md` (§5.6.9)
- Existing CKR: `ckr/test_ckr_v30_raw.py` (error paths)
- Pattern: `src/pkcs11_check/testcases/test_session_edge_cases.py`

**What to test:**
- C_LoginUser with CKU_CONTEXT_SPECIFIC (for CKA_ALWAYS_AUTHENTICATE keys)
- Skip if module doesn't support v3.0+ (check p11_interface_version)
- Basic login/logout cycle with context-specific login type

- [ ] **Step 1:** Read OASIS spec §5.6.9 (C_LoginUser)
- [ ] **Step 2:** Write test with @pytest.mark.requires_v30
- [ ] **Step 3:** Test context-specific login if module supports it
- [ ] **Step 4:** Run on Kryoptic (v3.2), verify skip on SoftHSM2 (v2.40)
- [ ] **Step 5:** Commit

---

### Task 4: C_SessionCancel (v3.0+)

**Files:**
- Extend: `src/pkcs11_check/testcases/test_v30_session.py` (created in Task 3)
- Reference: OASIS spec `session_mgmt_functions.md` (§5.6.10)
- Existing CKR: `ckr/test_ckr_v30_raw.py` (TestSessionCancelErrors)

**What to test:**
- Start a digest operation, cancel it mid-way, verify session is clean
- Start an encrypt operation, cancel, verify no state leak
- Verify CKR_OK returned on successful cancel

- [ ] **Step 1:** Read OASIS spec §5.6.10 (C_SessionCancel)
- [ ] **Step 2:** Add test: start digest, cancel, verify session usable
- [ ] **Step 3:** Add test: start encrypt, cancel, start new operation
- [ ] **Step 4:** Run on Kryoptic, commit

---

### Task 5: Dual-Function Operations

**Files:**
- Create: `src/pkcs11_check/testcases/test_dual_function.py`
- Reference: OASIS spec `dual-function_cryptographic_functions.md`
- Pattern: `src/pkcs11_check/testcases/test_multipart.py`

**What to test:**
- C_DigestEncryptUpdate: digest + encrypt in one pass
- C_DecryptDigestUpdate: decrypt + digest in one pass
- C_SignEncryptUpdate: sign + encrypt in one pass
- C_DecryptVerifyUpdate: decrypt + verify in one pass
- Compare result against separate operations (digest-then-encrypt vs dual)
- Skip if not supported (many modules don't implement dual-function)

- [ ] **Step 1:** Read OASIS spec for dual-function operations
- [ ] **Step 2:** Check python-pkcs11 fork for dual-function method support
- [ ] **Step 3:** Write DigestEncryptUpdate round-trip test (AES-CBC + SHA-256)
- [ ] **Step 4:** Write DecryptDigestUpdate test
- [ ] **Step 5:** Add xfail/skip for unsupported modules
- [ ] **Step 6:** Run tests, commit

---

### Task 6: C_DigestKey

**Files:**
- Extend: `src/pkcs11_check/testcases/test_digest.py` (existing digest test file)
- Reference: OASIS spec `message_digesting_functions.md` (§5.9.4)

**What to test:**
- Create a secret key, start digest operation, call DigestKey to include key material in hash
- Compare result with manual digest of same key bytes (if extractable)
- Skip if module doesn't support C_DigestKey (CKR_FUNCTION_NOT_SUPPORTED)

- [ ] **Step 1:** Read OASIS spec §5.9.4 (C_DigestKey)
- [ ] **Step 2:** Check python-pkcs11 fork for digest_key() method
- [ ] **Step 3:** Add test to test_digest.py: DigestKey with extractable secret key
- [ ] **Step 4:** Cross-verify with Python hashlib
- [ ] **Step 5:** Run tests, commit

---

### Task 7: Enhance C_GetTokenInfo / C_GetSlotInfo / C_GetInfo

**Files:**
- Extend: `src/pkcs11_check/testcases/test_token_flags.py` (existing)
- Reference: OASIS spec `slot_and_token_mgmt_functions.md` (§5.5.1, §5.5.2, §5.5.3) and `general_purpose_functions.md` (§5.2.3)

**What to test:**
- C_GetTokenInfo: verify all token flag bits documented in spec (CKF_RNG, CKF_WRITE_PROTECTED, etc.)
- C_GetTokenInfo: verify memory counters (ulTotalPublicMemory, etc.) are non-negative
- C_GetTokenInfo: verify session count fields
- C_GetSlotInfo: verify hardware/firmware version fields are populated
- C_GetSlotInfo: verify CKF_TOKEN_PRESENT, CKF_REMOVABLE_DEVICE, CKF_HW_SLOT flags
- C_GetInfo: verify cryptokiVersion >= {2, 40}

- [ ] **Step 1:** Read OASIS spec §5.5.1-3 and §5.2.3
- [ ] **Step 2:** Read existing TestTokenInfo, TestSlotInfo, TestLibraryInfo in test_token_flags.py
- [ ] **Step 3:** Add flag enumeration tests (iterate all defined CKF_* flags)
- [ ] **Step 4:** Add memory/session counter validation
- [ ] **Step 5:** Add version field validation
- [ ] **Step 6:** Run tests, commit

---

### Task 8: Enhance C_CopyObject

**Files:**
- Extend: `src/pkcs11_check/testcases/test_access_control.py` (existing TestCopyableFlag)
- Reference: OASIS spec `object_mgmt_functions.md` (§5.7.2)

**What to test:**
- Copy a secret key with modified label → verify label changed, other attrs preserved
- Copy a key with CKA_EXTRACTABLE changed → verify modification applied
- Verify CKA_COPYABLE=FALSE prevents copy
- Copy session object → verify copy is also session object
- Copy token object → verify copy is also token object (requires RW session)

- [ ] **Step 1:** Read OASIS spec §5.7.2 (C_CopyObject)
- [ ] **Step 2:** Read existing TestCopyableFlag tests
- [ ] **Step 3:** Add attribute-modification-during-copy tests
- [ ] **Step 4:** Add session/token object copy tests
- [ ] **Step 5:** Run tests, commit

---

### Task 9: Lint, Regression, Documentation

**Files:**
- Modify: `docs/test-coverage.md` — add new test files
- Modify: `docs/gap-analysis-oasis-spec.md` — update API function coverage

- [ ] **Step 1:** Run `uv run ruff check src/pkcs11_check/testcases/` — fix any issues
- [ ] **Step 2:** Run `uv run ruff format src/pkcs11_check/testcases/` on new files
- [ ] **Step 3:** Run full regression: `bash local-builds/test.sh softhsm2`
- [ ] **Step 4:** Run full regression: `bash local-builds/test.sh kryoptic`
- [ ] **Step 5:** Update docs/test-coverage.md with new test files
- [ ] **Step 6:** Update docs/gap-analysis-oasis-spec.md API coverage numbers
- [ ] **Step 7:** Commit all docs updates
