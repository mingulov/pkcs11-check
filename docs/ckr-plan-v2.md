# CKR 100% Coverage Implementation Plan

Spec: `docs/superpowers/specs/2026-03-19-100pct-ckr-coverage-design.md`
OASIS spec: https://github.com/oasis-tcs/pkcs11.git (`working/doc/spec/`)
Previous plan: `docs/ckr-plan.md` (completed: 244 entries, 119 tests)

---

## How to use

Each task is designed to be completed in **one iteration** of the Ralph loop.
**Use local builds** for fast iteration. Run `scripts/ckr-coverage-check.py` after every batch.

### Quick reference

```bash
# Validation script — the source of truth
uv run python scripts/ckr-coverage-check.py

# Test CKR suite
bash local-builds/test.sh softhsm2 -k "ckr" -v
bash local-builds/test.sh kryoptic -k "ckr" -v
bash local-builds/test.sh nss-softokn -k "ckr" -v

# Full suite regression
bash local-builds/test.sh softhsm2 -q && bash local-builds/test.sh kryoptic -q
```

### Task execution discipline

**Before implementing any task:**
1. Run `scripts/ckr-coverage-check.py` to see current gaps
2. Read the relevant OASIS spec section for exact CKR codes
3. Add entries / tests / fixes
4. Run validation script again — gaps should decrease
5. Verify on SoftHSM2 + Kryoptic + NSS softokn
6. Commit with task ID

**When a module returns unexpected CKR:** document in `docs/module-issues.md` with `compliance.note()`. NEVER silently pass.

## Completion promise

Validation script reports **0 missing function-specific entries** AND zero test regressions on SoftHSM2 + Kryoptic + NSS softokn.

---

## Phase 0 — Validation Script

The script is the source of truth. It parses the OASIS spec, extracts all (function, CKR) pairs, compares against `_ckr_spec.py`, and reports gaps.

- [ ] **0.1** Create `scripts/ckr-coverage-check.py` — parse all spec files in `/tmp/pkcs11/working/doc/spec/`, extract every `### C_*` function and its `Return values:` CKR list. Define universal CKR set (14 codes). For each function, compute: total CKRs, universal CKRs, function-specific CKRs. Load `_ckr_spec.py` and match entries. Output: per-function gap report + summary. If `/tmp/pkcs11/` doesn't exist, clone it first. Verify: `uv run python scripts/ckr-coverage-check.py` outputs current coverage and gap list.
- [ ] **0.2** Run script, record baseline. Document exact gap count in this plan.

## Phase 1a — Expand Existing Dicts (v2.40 core functions)

For each existing dict, add ALL missing function-specific CKR entries from the spec. Run validation script after each task. Mark multipart/wrapper-blocked entries as `testable=False`.

- [ ] **1a.1** Expand CKR_ENCRYPT — add every missing CKR for C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal. Run `scripts/ckr-coverage-check.py | grep C_Encrypt` to verify 0 gaps for these functions.
- [ ] **1a.2** Expand CKR_DECRYPT — same pattern for C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal.
- [ ] **1a.3** Expand CKR_SIGN — C_SignInit, C_Sign, C_SignUpdate, C_SignFinal, C_SignRecoverInit, C_SignRecover.
- [ ] **1a.4** Expand CKR_VERIFY — C_VerifyInit, C_Verify, C_VerifyUpdate, C_VerifyFinal, C_VerifyRecoverInit, C_VerifyRecover.
- [ ] **1a.5** Expand CKR_DIGEST — C_DigestInit, C_Digest, C_DigestUpdate, C_DigestKey, C_DigestFinal.
- [ ] **1a.6** Expand CKR_KEYGEN — C_GenerateKey, C_GenerateKeyPair.
- [ ] **1a.7** Expand CKR_WRAP — C_WrapKey, C_UnwrapKey.
- [ ] **1a.8** Expand CKR_DERIVE — C_DeriveKey.
- [ ] **1a.9** Expand CKR_KEM — C_EncapsulateKey, C_DecapsulateKey.
- [ ] **1a.10** Expand CKR_OBJECT — C_CreateObject, C_CopyObject, C_DestroyObject, C_GetObjectSize, C_GetAttributeValue, C_SetAttributeValue, C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal.
- [ ] **1a.11** Expand CKR_SESSION — C_OpenSession, C_CloseSession, C_CloseAllSessions, C_GetSessionInfo, C_Login, C_Logout.
- [ ] **1a.12** Expand CKR_SLOT_TOKEN — C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_GetMechanismInfo, C_InitToken, C_InitPIN, C_SetPIN, C_WaitForSlotEvent.
- [ ] **1a.13** Expand CKR_RANDOM — C_SeedRandom, C_GenerateRandom.
- [ ] **1a.14** Expand CKR_STATE — C_GetOperationState, C_SetOperationState.
- [ ] **1a.15** Expand CKR_GENERAL — C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList, C_GetFunctionStatus, C_CancelFunction.
- [ ] **1a.16** Validation checkpoint — run `scripts/ckr-coverage-check.py`. All v2.40 functions should show 0 gaps. Commit.

## Phase 1b — New Dicts for v3.0 Functions

- [ ] **1b.1** Create CKR_VERIFY_SIGNATURE dict — C_VerifySignatureInit, C_VerifySignature, C_VerifySignatureUpdate, C_VerifySignatureFinal. Add all function-specific CKRs. Mark `@pytest.mark.requires_v30`.
- [ ] **1b.2** Create CKR_DIGEST_XOF dict — C_DigestXofInit, C_DigestXof, C_DigestXofUpdate, C_DigestXofExtract, C_DigestXofFinal, C_DigestXofKeyValue. Mark `@pytest.mark.requires_v30`.
- [ ] **1b.3** Create CKR_MSG_ENCRYPT dict — C_MessageEncryptInit, C_EncryptMessage, C_EncryptMessageBegin, C_EncryptMessageNext, C_MessageEncryptFinal. Mark `@pytest.mark.requires_v30`.
- [ ] **1b.4** Create CKR_MSG_DECRYPT dict — C_MessageDecryptInit, C_DecryptMessage, etc.
- [ ] **1b.5** Create CKR_MSG_SIGN dict — C_MessageSignInit, C_SignMessage, etc.
- [ ] **1b.6** Create CKR_MSG_VERIFY dict — C_MessageVerifyInit, C_VerifyMessage, etc.
- [ ] **1b.7** Add C_LoginUser, C_SessionCancel, C_GetSessionValidationFlags to CKR_SESSION.
- [ ] **1b.8** Add C_GetInterface, C_GetInterfaceList to CKR_GENERAL.
- [ ] **1b.9** Validation checkpoint — run script. All v3.0 functions show 0 gaps.

## Phase 1c — New Dicts for v3.2 Functions

- [ ] **1c.1** Create CKR_WRAP_AUTH dict — C_WrapKeyAuthenticated, C_UnwrapKeyAuthenticated. Mark `@pytest.mark.requires_v32`.
- [ ] **1c.2** Create CKR_ASYNC dict — C_AsyncGetID, C_AsyncJoin. Document C_AsyncComplete as special case (dynamic return values).
- [ ] **1c.3** Expand CKR_KEM if any remaining entries for C_EncapsulateKey/C_DecapsulateKey.
- [ ] **1c.4** Validation checkpoint — all v3.2 functions show 0 gaps.

## Phase 1d — Dual-Function and Special Cases

- [ ] **1d.1** Create CKR_DUAL dict — C_DigestEncryptUpdate, C_DecryptDigestUpdate, C_SignEncryptUpdate, C_DecryptVerifyUpdate.
- [ ] **1d.2** Document special cases: C_AsyncComplete (dynamic), C_GetFunctionStatus/C_CancelFunction (legacy, CKR_FUNCTION_NOT_PARALLEL only).
- [ ] **1d.3** Final validation — `scripts/ckr-coverage-check.py` reports **0 missing function-specific entries**. Commit milestone.

## Phase 2 — Raw ctypes Tests (unlock testable=False)

Use `pkcs11.raw.RawPKCS11` to test conditions blocked by wrapper. All run in subprocess.

- [ ] **2.1** Attribute permission tests — create `test_ckr_raw_attrs.py`: CKA_ENCRYPT=False + C_EncryptInit, CKA_DECRYPT=False + C_DecryptInit, CKA_SIGN=False + C_SignInit, CKA_VERIFY=False + C_VerifyInit, CKA_DERIVE=False + C_DeriveKey. Each → CKR_KEY_FUNCTION_NOT_PERMITTED. Verify on SoftHSM2 + Kryoptic.
- [ ] **2.2** Additional multipart tests — expand `test_ckr_raw_multipart.py`: C_DecryptFinal without Init, C_SignFinal without Init, C_VerifyUpdate without Init, C_VerifyFinal without Init. All → CKR_OPERATION_NOT_INITIALIZED.
- [ ] **2.3** Additional state tests — expand `test_ckr_raw_state.py`: double C_SignInit, double C_DecryptInit, C_DigestInit then C_EncryptInit (cross-op).
- [ ] **2.4** Additional buffer tests — expand `test_ckr_raw_buffer.py`: C_Sign with 1-byte output, C_SignFinal with 1-byte output, C_GetAttributeValue with 1-byte buffer.
- [ ] **2.5** Flip testable=False → testable=True for all entries now covered by raw tests. Run validation script to confirm.
- [ ] **2.6** Validation checkpoint — all 3 local targets. Count tests.

## Phase 3 — Destructive Subprocess Tests

Each test runs in subprocess with temporary token. Main token untouched.

- [ ] **3.1** Create `test_ckr_destructive.py` — all @subprocess + @destructive: (a) C_InitToken with open session → CKR_SESSION_EXISTS. (b) C_InitToken with wrong SO PIN → CKR_PIN_INCORRECT. (c) C_SetPIN with wrong old PIN → CKR_PIN_INCORRECT. (d) C_SetPIN with too-short new PIN → CKR_PIN_LEN_RANGE. (e) C_InitPIN without SO login → CKR_USER_NOT_LOGGED_IN. Verify on SoftHSM2.
- [ ] **3.2** PIN lockout test — C_Login with wrong PIN N times → CKR_PIN_LOCKED. Mark @destructive. Use fresh temp token. Document lockout threshold per module.
- [ ] **3.3** Flip testable=False for destructive entries covered.

## Phase 4 — Fault-Proxy Upgrade

Upgrade fault-proxy.c to intercept all C_* functions for device/token error injection.

- [ ] **4.1** Upgrade `fault-proxy.c` — instead of pass-through, build full CK_FUNCTION_LIST with intercepting wrappers for ALL 68 functions. Each checks `should_inject(func_name)` before delegating. ~600 lines C. Verify: build + basic encrypt/decrypt through proxy.
- [ ] **4.2** Expand `test_ckr_fault_inject.py` — inject: CKR_DEVICE_REMOVED on C_Encrypt, CKR_DEVICE_ERROR on C_Sign, CKR_DEVICE_MEMORY on C_GenerateKey, CKR_TOKEN_NOT_PRESENT on C_GetTokenInfo. Verify actual injection works (not just pass-through).
- [ ] **4.3** Flip testable=False for device/token entries covered.

## Phase 5 — Universal CKR Infrastructure Tests

- [ ] **5.1** Create `test_ckr_universal.py` — parametrized tests verifying each of the 14 universal CKR codes: (a) Present in correct `_UNIVERSAL` / `_SESSION_UNIVERSAL` / `_TOKEN_UNIVERSAL` tuple. (b) `full_compat()` includes it. (c) At least one real trigger (e.g., CKR_SESSION_HANDLE_INVALID via closed session, CKR_DEVICE_ERROR via fault-proxy, CKR_CRYPTOKI_NOT_INITIALIZED via post-Finalize call).
- [ ] **5.2** Update `full_compat()` if any universal codes are missing (CKR_OPERATION_NOT_VALIDATED, CKR_TOKEN_NOT_INITIALIZED).

## Phase 6 — Document Untestable + Final

- [ ] **6.1** For each truly untestable CKR, add entry with `testable=False, rationale="..."`: CKR_MUTEX_BAD, CKR_MUTEX_NOT_LOCKED, CKR_CANCEL, CKR_FUNCTION_NOT_PARALLEL, CKR_PENDING (most contexts), CKR_FUNCTION_REJECTED (token-specific), C_AsyncComplete (dynamic returns).
- [ ] **6.2** Update `docs/ckr-coverage.md` — final numbers from validation script. Per-function matrix. Per-module deviation summary.
- [ ] **6.3** Final regression — `bash local-builds/test.sh softhsm2 -q && bash local-builds/test.sh kryoptic -q`. Zero failures.
- [ ] **6.4** Update `docs/master-plan.md` — mark CKR coverage as complete.
- [ ] **6.5** **Handoff to master-plan.md** — CKR 100% coverage achieved.

---

## Recommended loop prompt

```
/ralph-loop:ralph-loop "/using-superpowers Pick the highest-priority unfinished task from docs/ckr-plan-v2.md. Implementation rules: (1) If /tmp/pkcs11/ doesn't exist: git clone --depth 1 https://github.com/oasis-tcs/pkcs11.git /tmp/pkcs11. (2) Run scripts/ckr-coverage-check.py before AND after each task to track progress. (3) Use _error_tuples.py — NEVER generic PKCS11Error catches. (4) Unexpected CKR: document in module-issues.md with compliance.note(). (5) Verify on SoftHSM2 + Kryoptic + NSS softokn after each change. (6) For medium/large tasks: plan first (read spec section), implement, verify, gap-check, commit. (7) Commit with task ID." --completion-promise "All tasks in docs/ckr-plan-v2.md are marked done"
```
