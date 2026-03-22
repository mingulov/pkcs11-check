# Test Failure Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix remaining test failures identified in docs/test-failure-report.md where the root cause is in pkcs11-check (not module bugs). For tests where behavior legitimately varies across modules, convert hard failures to xfail/compliance notes.

**Architecture:** Each task investigates one failing test area, determines if it's our bug (fix template/params), a spec ambiguity (xfail with compliance note), or a module limitation (xfail with module name). No test logic should be weakened - only corrected.

**Tech Stack:** Python, pytest, PKCS#11 OASIS spec at `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/`

**Key principle:** Check OASIS spec for each failure. If spec says MUST/SHALL, the test is correct and modules that fail have bugs (keep as failure or use `--ckr-strict`). If spec says MAY/SHOULD or is silent, xfail with compliance note.

---

### Task 1: test_aes_ctr_different_keys (softhsm2, kryoptic, opencryptoki)

**Files:**
- Check: `src/pkcs11_check/testcases/test_aes_modes.py`
- Check: `artifacts/{softhsm2,kryoptic}/results.json` for longrepr

- [ ] Read the test and the error from artifacts
- [ ] Check if the key template is missing ENCRYPT attribute
- [ ] Check if CTR params (nonce) are passed correctly via CTRParams
- [ ] Fix template/params or xfail if module limitation
- [ ] Run locally: `bash local-builds/test.sh softhsm2 -v -- "src/pkcs11_check/testcases/test_aes_modes.py::TestAESCTR::test_aes_ctr_different_keys"`
- [ ] Commit

---

### Task 2: test_concurrent_sessions (nss, qryptotoken, tpm2)

**Files:**
- Check: `src/pkcs11_check/testcases/test_concurrent_sessions.py`

- [ ] Read the test - does it assume key handles work across sessions?
- [ ] Check OASIS spec `session_mgmt_functions.md` - are session objects visible to other sessions on the same token?
- [ ] Per spec: session objects are visible to all sessions of the same application. If module doesn't share, that's a module limitation -> xfail
- [ ] Fix or xfail with compliance note referencing spec section
- [ ] Commit

---

### Task 3: test_key_flags (CKA_LOCAL, CKA_NEVER_EXTRACTABLE)

**Files:**
- Check: `src/pkcs11_check/testcases/test_key_flags.py`
- Spec: `key_objects.md`

- [ ] Read test_generated_rsa_keypair_is_local - what does it assert?
- [ ] Check OASIS spec for CKA_LOCAL: "Set to CK_TRUE when key was generated locally (i.e., on the token)" - this is REQUIRED for generate_keypair
- [ ] If modules don't set CKA_LOCAL, that's a module bug, not ours. Keep as failure or xfail with spec reference.
- [ ] Read test_extractable_and_never_extractable_consistent
- [ ] Check spec: CKA_NEVER_EXTRACTABLE should be TRUE if key was never extractable. Some modules may not track this.
- [ ] Fix or xfail with compliance note
- [ ] Commit

---

### Task 4: test_object_size (nss, qryptotoken, tpm2)

**Files:**
- Check: `src/pkcs11_check/testcases/test_object_size.py`
- Spec: `object_mgmt_functions.md` for C_GetObjectSize

- [ ] Read test - what does it assert about RSA vs AES size?
- [ ] Check spec: C_GetObjectSize "obtains the size of an object in bytes" but also "may not be accurate"
- [ ] If spec says size is approximate, the test assertion may be too strict
- [ ] Fix assertion or xfail with spec note about approximate sizes
- [ ] Commit

---

### Task 5: test_object_visibility cross-session modification (7 providers)

**Files:**
- Check: `src/pkcs11_check/testcases/test_object_visibility.py`
- Spec: `objects.md`

- [ ] Read test - modifying CKA_VALUE across sessions
- [ ] Check spec: session objects visible to all sessions, but C_SetAttributeValue may behave differently
- [ ] If spec allows variation, xfail on modules that don't support cross-session modification
- [ ] Commit

---

### Task 6: test_ro_session_restrictions unwrap (6 providers)

**Files:**
- Check: `src/pkcs11_check/testcases/test_ro_session_restrictions.py`
- Spec: `session_mgmt_functions.md`, `object_mgmt_functions.md`

- [ ] Read test_unwrap_to_session_object_in_ro_succeeds and test_unwrap_to_token_object_in_ro_fails
- [ ] Check spec: can RO sessions create session objects via C_UnwrapKey?
- [ ] Per spec: RO sessions CAN create session objects. Modules that reject this have a bug.
- [ ] Fix test or xfail if modules are overly restrictive
- [ ] Commit

---

### Task 7: test_sensitivity (default EXTRACTABLE) (6 providers)

**Files:**
- Check: `src/pkcs11_check/testcases/test_sensitivity.py`
- Spec: `key_objects.md` for CKA_EXTRACTABLE defaults

- [ ] Read test_non_extractable_by_default
- [ ] Check spec: what is the default for CKA_EXTRACTABLE? Spec says implementation-dependent.
- [ ] If spec doesn't mandate a default, test should not assert a specific default -> xfail with compliance note
- [ ] Commit

---

### Task 8: test_subprocess_safety reload (5 providers)

**Files:**
- Check: `src/pkcs11_check/testcases/test_subprocess_safety.py`

- [ ] Read test_reload_cycle_5x - what does it do?
- [ ] C_Finalize + C_Initialize 5 times in a subprocess
- [ ] Some modules crash or return errors on re-init. This is a module robustness test.
- [ ] If modules crash, that's a module bug. If they return CKR errors, xfail.
- [ ] Commit

---

### Task 9: test_tookan copy escalation (5 providers)

**Files:**
- Check: `src/pkcs11_check/testcases/test_tookan.py`
- Spec: `object_mgmt_functions.md` for C_CopyObject

- [ ] Read test_extractable_cannot_escalate_on_copy
- [ ] Per spec: copying a key should NOT allow escalating CKA_EXTRACTABLE from FALSE to TRUE
- [ ] If modules allow this, it's a SECURITY issue (the test should fail, not xfail)
- [ ] Use compliance.note() for modules that allow escalation
- [ ] Commit

---

### Task 10: test_hkdf_key_gen_usable_for_derive (6 providers)

**Files:**
- Check: `src/pkcs11_check/testcases/test_hkdf_extended.py`

- [ ] Read test - generates key via HKDF_KEY_GEN, then uses for HKDF_DERIVE
- [ ] Check if the derive template is correct (KEY_TYPE, VALUE_LEN, etc.)
- [ ] The HKDF_DERIVE param structure may need specific fields
- [ ] Fix template or xfail if module doesn't support the derive chain
- [ ] Commit

---

### Task 11: test_v30_session cancel (5 providers)

**Files:**
- Check: `src/pkcs11_check/testcases/test_v30_session.py`
- Spec: `session_mgmt_functions.md` for C_SessionCancel

- [ ] Read test_cancel_after_digest_init_subprocess
- [ ] C_SessionCancel is v3.0+. Many modules don't implement it.
- [ ] If module returns FUNCTION_NOT_SUPPORTED, xfail (already handled?)
- [ ] If module crashes (Kryoptic), that's a module bug
- [ ] Commit

---

### Task 12: Document module bugs in docs/module-issues.md

**Files:**
- Modify: `docs/module-issues.md`

- [ ] Add BouncyHSM: crashes on 1MB+ data (test_blake2b, test_buffers, test_digest, test_large_objects)
- [ ] Add SoftHSM2-main: EC regression in dev branch (4715 ECDSA/ECDH crashes)
- [ ] Add Qryptotoken: calls abort() instead of returning CKR codes (218 crashes)
- [ ] Add OpenCryptoki: crash on SSL3 master key derive
- [ ] Commit

---

### Task 13: Update CLAUDE.md and memory

**Files:**
- Modify: `CLAUDE.md`
- Modify: `/home/user/.claude/projects/-home-user-src-m-pkcs11-check/memory/project_pkcs11_check.md`

- [ ] Update CLAUDE.md: JSONL reporting, iterative deselect, TLS mechanisms, skip_reasons, file-based deselect
- [ ] Update CLAUDE.md: new Docker targets (nss-main, opencryptoki-master, kryoptic PQC/FIPS)
- [ ] Update CLAUDE.md: docker/test-all.sh
- [ ] Update memory with current project state
- [ ] Commit

---

### Task 14: Refresh docs/test-failure-report.md

- [ ] Re-run the analysis script from this session against current artifacts
- [ ] Update the report with fixed items marked as resolved
- [ ] Add remaining items with their current status
- [ ] Commit
