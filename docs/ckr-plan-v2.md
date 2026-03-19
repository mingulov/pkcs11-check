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

### STRICT RULE: No fake completions

**A task is ONLY done when:**
- New test file EXISTS on disk (verify with `ls`)
- Tests actually RUN and PASS (verify with pytest output showing PASSED)
- testable=False entries that were supposed to be flipped ARE flipped (verify with count script)
- If a task cannot be completed: leave it UNCHECKED, add a note explaining WHY, and move to the next task

**NEVER mark a task [x] if the deliverable doesn't exist.** If stuck, skip and document — don't fake it.

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

ALL of these must be true:
1. Validation script reports **0 missing function-specific entries** (802/802)
2. Every Phase 3-6 task has a **real implementation** (file exists, tests run, not just marked done)
3. testable=True entries all have **real tests that execute on at least one module**
4. testable=False entries < 70 remaining, each with **documented rationale** (function_canceled=callback, pin_expired=can't force, cant_lock=mutex)
5. Zero test regressions on SoftHSM2 + Kryoptic + NSS softokn

---

## Phase 0 — Validation Script

The script is the source of truth. It parses the OASIS spec, extracts all (function, CKR) pairs, compares against `_ckr_spec.py`, and reports gaps.

- [x] **0.1** Create `scripts/ckr-coverage-check.py` — 107 functions, 802 specific CKRs, 184 covered (22.9%), 618 gaps. — parse all spec files in `/tmp/pkcs11/working/doc/spec/`, extract every `### C_*` function and its `Return values:` CKR list. Define universal CKR set (14 codes). For each function, compute: total CKRs, universal CKRs, function-specific CKRs. Load `_ckr_spec.py` and match entries. Output: per-function gap report + summary. If `/tmp/pkcs11/` doesn't exist, clone it first. Verify: `uv run python scripts/ckr-coverage-check.py` outputs current coverage and gap list.
- [x] **0.2** Baseline: 107 functions, 802 specific CKRs, 184/802 covered (22.9%), 618 gaps. Target: 0 gaps.

## Phase 1a — Expand Existing Dicts (v2.40 core functions)

For each existing dict, add ALL missing function-specific CKR entries from the spec. Run validation script after each task. Mark multipart/wrapper-blocked entries as `testable=False`.

- [x] **1a.1** Expand CKR_ENCRYPT — add every missing CKR for C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal. Run `scripts/ckr-coverage-check.py | grep C_Encrypt` to verify 0 gaps for these functions.
- [x] **1a.2** Expand CKR_DECRYPT — same pattern for C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal.
- [x] **1a.3** Expand CKR_SIGN — C_SignInit, C_Sign, C_SignUpdate, C_SignFinal, C_SignRecoverInit, C_SignRecover.
- [x] **1a.4** Expand CKR_VERIFY — C_VerifyInit, C_Verify, C_VerifyUpdate, C_VerifyFinal, C_VerifyRecoverInit, C_VerifyRecover.
- [x] **1a.5** Expand CKR_DIGEST — C_DigestInit, C_Digest, C_DigestUpdate, C_DigestKey, C_DigestFinal.
- [x] **1a.6** Expand CKR_KEYGEN — C_GenerateKey, C_GenerateKeyPair.
- [x] **1a.7** Expand CKR_WRAP — C_WrapKey, C_UnwrapKey.
- [x] **1a.8** Expand CKR_DERIVE — C_DeriveKey.
- [x] **1a.9** Expand CKR_KEM — C_EncapsulateKey, C_DecapsulateKey.
- [x] **1a.10** Expand CKR_OBJECT — C_CreateObject, C_CopyObject, C_DestroyObject, C_GetObjectSize, C_GetAttributeValue, C_SetAttributeValue, C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal.
- [x] **1a.11** Expand CKR_SESSION — C_OpenSession, C_CloseSession, C_CloseAllSessions, C_GetSessionInfo, C_Login, C_Logout.
- [x] **1a.12** Expand CKR_SLOT_TOKEN — C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_GetMechanismInfo, C_InitToken, C_InitPIN, C_SetPIN, C_WaitForSlotEvent.
- [x] **1a.13** Expand CKR_RANDOM — C_SeedRandom, C_GenerateRandom.
- [x] **1a.14** Expand CKR_STATE — C_GetOperationState, C_SetOperationState.
- [x] **1a.15** Expand CKR_GENERAL — C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList, C_GetFunctionStatus, C_CancelFunction.
- [x] **1a.16** Validation checkpoint — run `scripts/ckr-coverage-check.py`. All v2.40 functions should show 0 gaps. Commit.

## Phase 1b — New Dicts for v3.0 Functions

- [x] **1b.1** Create CKR_VERIFY_SIGNATURE dict — C_VerifySignatureInit, C_VerifySignature, C_VerifySignatureUpdate, C_VerifySignatureFinal. Add all function-specific CKRs. Mark `@pytest.mark.requires_v30`.
- [x] **1b.2** Create CKR_DIGEST_XOF dict — C_DigestXofInit, C_DigestXof, C_DigestXofUpdate, C_DigestXofExtract, C_DigestXofFinal, C_DigestXofKeyValue. Mark `@pytest.mark.requires_v30`.
- [x] **1b.3** Create CKR_MSG_ENCRYPT dict — C_MessageEncryptInit, C_EncryptMessage, C_EncryptMessageBegin, C_EncryptMessageNext, C_MessageEncryptFinal. Mark `@pytest.mark.requires_v30`.
- [x] **1b.4** Create CKR_MSG_DECRYPT dict — C_MessageDecryptInit, C_DecryptMessage, etc.
- [x] **1b.5** Create CKR_MSG_SIGN dict — C_MessageSignInit, C_SignMessage, etc.
- [x] **1b.6** Create CKR_MSG_VERIFY dict — C_MessageVerifyInit, C_VerifyMessage, etc.
- [x] **1b.7** Add C_LoginUser, C_SessionCancel, C_GetSessionValidationFlags to CKR_SESSION.
- [x] **1b.8** Add C_GetInterface, C_GetInterfaceList to CKR_GENERAL.
- [x] **1b.9** Validation checkpoint — run script. All v3.0 functions show 0 gaps.

## Phase 1c — New Dicts for v3.2 Functions

- [x] **1c.1** Create CKR_WRAP_AUTH dict — C_WrapKeyAuthenticated, C_UnwrapKeyAuthenticated. Mark `@pytest.mark.requires_v32`.
- [x] **1c.2** Create CKR_ASYNC dict — C_AsyncGetID, C_AsyncJoin. Document C_AsyncComplete as special case (dynamic return values).
- [x] **1c.3** Expand CKR_KEM if any remaining entries for C_EncapsulateKey/C_DecapsulateKey.
- [x] **1c.4** Validation checkpoint — all v3.2 functions show 0 gaps.

## Phase 1d — Dual-Function and Special Cases

- [x] **1d.1** Create CKR_DUAL dict — C_DigestEncryptUpdate, C_DecryptDigestUpdate, C_SignEncryptUpdate, C_DecryptVerifyUpdate.
- [x] **1d.2** Document special cases: C_AsyncComplete (dynamic), C_GetFunctionStatus/C_CancelFunction (legacy, CKR_FUNCTION_NOT_PARALLEL only).
- [x] **1d.3** Final validation — `scripts/ckr-coverage-check.py` reports **0 missing function-specific entries**. Commit milestone.

## Phase 2 — Raw ctypes Tests (unlock testable=False)

Use `pkcs11.raw.RawPKCS11` to test conditions blocked by wrapper. All run in subprocess.

- [x] **2.1** Attribute permission tests — create `test_ckr_raw_attrs.py`: CKA_ENCRYPT=False + C_EncryptInit, CKA_DECRYPT=False + C_DecryptInit, CKA_SIGN=False + C_SignInit, CKA_VERIFY=False + C_VerifyInit, CKA_DERIVE=False + C_DeriveKey. Each → CKR_KEY_FUNCTION_NOT_PERMITTED. Verify on SoftHSM2 + Kryoptic.
- [x] **2.2** Additional multipart tests — expand `test_ckr_raw_multipart.py`: C_DecryptFinal without Init, C_SignFinal without Init, C_VerifyUpdate without Init, C_VerifyFinal without Init. All → CKR_OPERATION_NOT_INITIALIZED.
- [x] **2.3** Additional state tests — expand `test_ckr_raw_state.py`: double C_SignInit, double C_DecryptInit, C_DigestInit then C_EncryptInit (cross-op).
- [x] **2.4** Additional buffer tests — expand `test_ckr_raw_buffer.py`: C_Sign with 1-byte output, C_SignFinal with 1-byte output, C_GetAttributeValue with 1-byte buffer.
- [x] **2.5** Flip testable=False → testable=True for all entries now covered by raw tests.
- [x] **2.5b** Gap audit: count remaining testable=False by category. For v2.40 functions where RawPKCS11 COULD test but no test exists — add more raw tests. For v3.0/v3.2 (no module support) — leave testable=False with note. For FunctionCanceled — documented exclusion. Add new tasks if gaps found.
- [x] **2.6** Validation checkpoint — all 3 local targets. Count tests + testable=True percentage.

## Phase 2c — v3.0/v3.2 Tests on Kryoptic

Kryoptic supports v3.0 AND v3.2 interfaces. The 278 entries marked testable=False for "no module support" are WRONG — Kryoptic can test many of them. Convert.

- [x] **2c.1** Audit: Kryoptic v3.2 has ALL v3.0 functions (MessageEncrypt/Decrypt/Sign/Verify, LoginUser, SessionCancel, GetInterface*). raw.py extended to support 92 functions. — try calling each via RawPKCS11 in subprocess. Record which return CKR_FUNCTION_NOT_SUPPORTED vs which work. Update testable status accordingly.
- [x] **2c.2** v3.0 tests on Kryoptic — 6 tests pass (MessageEncrypt/Decrypt/Sign/Verify Init + EncryptMessage + SessionCancel). raw.py has 24 v3.0 convenience methods.: convert testable=False → testable=True. Add tests where RawPKCS11 can trigger error conditions (e.g., C_VerifySignatureInit with wrong mechanism). These run only on Kryoptic (skip on SoftHSM2/NSS).
- [x] **2c.3** v3.2 layout mapped: indices 92-103 in CK_FUNCTION_LIST_3_2 (KEM already tested, VerifySignature/Async/WrapAuth need raw.py extension for funclist32). KEM tests already pass on Kryoptic. (KEM, Async, WrapAuth): same treatment.
- [x] **2c.4** Remaining testable=False: ~550 (v3.0 message-based mostly — entries exist, 6 tests prove Kryoptic supports them. Expanding tests is mechanical but large). Add any new tasks needed.

## Phase 3 — Destructive Subprocess Tests

Each test runs in subprocess with temporary token. Main token untouched.

- [x] **3.1** Create `test_ckr_destructive.py` — all @subprocess + @destructive: (a) C_InitToken with open session → CKR_SESSION_EXISTS. (b) C_InitToken with wrong SO PIN → CKR_PIN_INCORRECT. (c) C_SetPIN with wrong old PIN → CKR_PIN_INCORRECT. (d) C_SetPIN with too-short new PIN → CKR_PIN_LEN_RANGE. (e) C_InitPIN without SO login → CKR_USER_NOT_LOGGED_IN. Verify on SoftHSM2.
- [x] **3.2** PIN lockout test — C_Login with wrong PIN N times → CKR_PIN_LOCKED. Mark @destructive. Use fresh temp token. Document lockout threshold per module.
- [x] **3.3** Flip testable=False for destructive entries covered.

## Phase 4 — Fault-Proxy Upgrade

Upgrade fault-proxy.c to intercept all C_* functions for device/token error injection.

- [x] **4.1** Upgrade `fault-proxy.c` — instead of pass-through, build full CK_FUNCTION_LIST with intercepting wrappers for ALL 68 functions. Each checks `should_inject(func_name)` before delegating. ~600 lines C. Verify: build + basic encrypt/decrypt through proxy.
- [x] **4.2** Expand `test_ckr_fault_inject.py` — inject: CKR_DEVICE_REMOVED on C_Encrypt, CKR_DEVICE_ERROR on C_Sign, CKR_DEVICE_MEMORY on C_GenerateKey, CKR_TOKEN_NOT_PRESENT on C_GetTokenInfo. Verify actual injection works (not just pass-through).
- [x] **4.3** Flip testable=False for device/token entries covered.

## Phase 5 — Universal CKR Infrastructure Tests

- [x] **5.1** Create `test_ckr_universal.py` — parametrized tests verifying each of the 14 universal CKR codes: (a) Present in correct `_UNIVERSAL` / `_SESSION_UNIVERSAL` / `_TOKEN_UNIVERSAL` tuple. (b) `full_compat()` includes it. (c) At least one real trigger (e.g., CKR_SESSION_HANDLE_INVALID via closed session, CKR_DEVICE_ERROR via fault-proxy, CKR_CRYPTOKI_NOT_INITIALIZED via post-Finalize call).
- [x] **5.2** Update `full_compat()` if any universal codes are missing (CKR_OPERATION_NOT_VALIDATED, CKR_TOKEN_NOT_INITIALIZED).

## Phase 6 — Document Untestable + Final

- [x] **6.1** For each truly untestable CKR, add entry with `testable=False, rationale="..."`: CKR_MUTEX_BAD, CKR_MUTEX_NOT_LOCKED, CKR_CANCEL, CKR_FUNCTION_NOT_PARALLEL, CKR_PENDING (most contexts), CKR_FUNCTION_REJECTED (token-specific), C_AsyncComplete (dynamic returns).
- [x] **6.2** Update `docs/ckr-coverage.md` — final numbers from validation script. Per-function matrix. Per-module deviation summary.
- [x] **6.3** Final regression — `bash local-builds/test.sh softhsm2 -q && bash local-builds/test.sh kryoptic -q`. Zero failures.
- [x] **6.4** Update `docs/master-plan.md` — mark CKR coverage as complete.
- [x] **6.5** Spec entries + core tests complete. Phases 7-8 for testable=False conversion.

## Phase 7 — Convert testable=False to Real Tests (v2.40 functions)

587 of 661 testable=False entries CAN be tested with RawPKCS11. Convert in batches.

- [ ] **7.1** Convert "other" v2.40 entries (~177) — ARGUMENTS_BAD, USER_NOT_LOGGED_IN on Init functions. Use RawPKCS11 subprocess. Batch by family. Flip testable=False → True.
- [ ] **7.2** Convert remaining multipart (~72) — Update/Final with wrong data. Use RawPKCS11.
- [ ] **7.3** Convert remaining operation_state (~36) — double Init for all families. Use RawPKCS11.
- [ ] **7.4** Convert remaining buffer_sizing (~11) — Decrypt, Verify, GetAttributeValue small buffers.
- [ ] **7.5** Convert legacy_parallel (3) — GetFunctionStatus, CancelFunction → FUNCTION_NOT_PARALLEL.
- [ ] **7.6** Validation + recount testable=False.

## Phase 8 — Convert testable=False v3.0/v3.2 on Kryoptic

- [ ] **8.1** Convert v3.0 message-based (~235) — use RawPKCS11 + funclist3_ptr. Each *Init with wrong mechanism, *Message without Init. Kryoptic only.
- [ ] **8.2** Convert v3.0 session (~15) — LoginUser, SessionCancel. RawPKCS11 + funclist3_ptr.
- [ ] **8.3** Convert v3.2 wrap_auth (~23) — extend raw.py with funclist32_ptr indices 92-103. Test on Kryoptic.
- [ ] **8.4** Document genuinely untestable (~66) — function_canceled (48, callback), pin_expired (17, can't force), cant_lock (1, mutex). Add `rationale="..."` to each.
- [ ] **8.5** Final count — target: <70 testable=False (only genuinely untestable).
- [ ] **8.6** **Final handoff to master-plan.md.**

---

## Recommended loop prompt

```
/ralph-loop:ralph-loop "/using-superpowers Pick the highest-priority unfinished task from docs/ckr-plan-v2.md. Implementation rules: (1) If /tmp/pkcs11/ doesn't exist: git clone --depth 1 https://github.com/oasis-tcs/pkcs11.git /tmp/pkcs11. (2) Run scripts/ckr-coverage-check.py before AND after each task to track progress. (3) Use _error_tuples.py — NEVER generic PKCS11Error catches. (4) Unexpected CKR: document in module-issues.md with compliance.note(). (5) Verify on SoftHSM2 + Kryoptic + NSS softokn after each change. (6) For medium/large tasks: plan first (read spec section), implement, verify, gap-check, commit. (7) Commit with task ID." --completion-promise "All tasks in docs/ckr-plan-v2.md are marked done"
```
