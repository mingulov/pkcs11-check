# Final Cleanup -- All Remaining Items

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Use **Sonnet 4.6** for implementation tasks, **Opus 4.6** for review and investigation tasks.

**Goal:** Close every remaining gap identified by the deep gap analysis. Covers unexecuted Plan 7 tasks, remaining test bugs, meta-test fixes, and memory updates.

**Architecture:** 10 tasks across 4 phases. All tasks are independent.

**Tech Stack:** Python 3.11+, pytest, pkcs11_check.raw

---

## Phase 1: Remaining Test Bugs (Tasks 1-3)

### Task 1: Add keygen_mech to 5 legacy sign mechanisms (Sonnet)

**Impact:** Enables mechanism-driven tests for 5 currently-skipped mechanisms.

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_registry/_rsa.py`
- Modify: `src/pkcs11_check/testcases/mechanism_registry/_hmac.py` or `_misc.py`

- [ ] **Step 1:** Find and fix these 5 entries:

| Mechanism | File | Fix keygen_mech | Also add |
|-----------|------|----------------|----------|
| CKM_MD2_RSA_PKCS | `_rsa.py` | `CKM_RSA_PKCS_KEY_PAIR_GEN` | `is_keypair=True, key_type=CKK_RSA, key_sizes=(2048, 4096), keygen_recipe=_rsa` |
| CKM_MD5_RSA_PKCS | `_rsa.py` | `CKM_RSA_PKCS_KEY_PAIR_GEN` | same |
| CKM_MD2_HMAC | `_hmac.py` | `CKM_GENERIC_SECRET_KEY_GEN` | `key_type=CKK_MD2_HMAC` (or CKK_GENERIC_SECRET) |
| CKM_MD2_HMAC_GENERAL | `_hmac.py` | `CKM_GENERIC_SECRET_KEY_GEN` | same |
| CKM_MD5_HMAC_GENERAL | `_hmac.py` | `CKM_GENERIC_SECRET_KEY_GEN` | `key_type=CKK_MD5_HMAC` (or CKK_GENERIC_SECRET) |

Read each file to find the existing entries and check their current fields before modifying.

- [ ] **Step 2:** Lint: `uv run ruff check src/pkcs11_check/testcases/mechanism_registry/`

- [ ] **Step 3:** Commit:
```bash
git commit -m 'fix: add keygen_mech to MD2/MD5 RSA and HMAC registry entries'
```

---

### Task 2: Fix meta-test timeout for uv build (Sonnet)

**Impact:** Fixes 1 meta-test failure (test_raw_pack.py timeout).

**Files:**
- Modify: `tests/test_raw_pack.py`

- [ ] **Step 1:** Read `tests/test_raw_pack.py`, find `test_sdist_and_wheel_include_vendored_standard_headers_and_generated_raw_modules`.

- [ ] **Step 2:** The test runs `uv build` which takes >60s. Increase the timeout. Look for `@pytest.mark.timeout()` decorator or add one:
```python
@pytest.mark.timeout(300)  # uv build can take up to 5 minutes
def test_sdist_and_wheel_include_vendored_standard_headers_and_generated_raw_modules(tmp_path):
```

- [ ] **Step 3:** Lint and commit:
```bash
git commit -m 'fix: increase meta-test timeout for uv build to 300s'
```

---

### Task 3: Fix coverage alias tracking for CKM_ECDSA_KEY_PAIR_GEN (Sonnet)

**Impact:** Fixes false "not invoked" in compliance report for 1 mechanism.

**Files:**
- Modify: `src/pkcs11_check/compliance_report.py` or wherever mechanism invocation is tracked

- [ ] **Step 1:** Search for how mechanism invocation is tracked:
```bash
grep -rn "used_mechanisms\|invoked_mechanisms\|_used_mechs" src/pkcs11_check/
```

- [ ] **Step 2:** The tracking should resolve aliases. CKM_ECDSA_KEY_PAIR_GEN (0x1040) has the same numeric ID as CKM_EC_KEY_PAIR_GEN. When reporting "not invoked", check if ANY name for the same ID was invoked.

- [ ] **Step 3:** Fix and commit:
```bash
git commit -m 'fix: track mechanism coverage by ID to handle aliases'
```

---

## Phase 2: Uncovered Mechanisms (Tasks 4-6)

### Task 4: Verify DES encrypt-data derive mechanisms (Opus investigation)

**Impact:** 4 mechanisms: CKM_DES_ECB/CBC_ENCRYPT_DATA, CKM_DES3_ECB/CBC_ENCRYPT_DATA.

- [ ] **Step 1:** Read `src/pkcs11_check/testcases/test_mech_derive.py` -- check if the `_derive_aes_ecb()` helper or a similar function handles CKM_DES*_ENCRYPT_DATA mechanisms. These derive mechanisms need a DES base key (not AES).

- [ ] **Step 2:** Check if the derive test's dispatch chain routes DES encrypt-data mechanisms correctly. The `string_data` param_recipe is already set.

- [ ] **Step 3:** If the derive test skips DES variants because it can only generate AES base keys, add DES base key generation. If the test already handles it but modules don't support it, document as module finding.

- [ ] **Step 4:** Commit if changes made.

---

### Task 5: Add CK_PBE_PARAMS packer for PBE mechanisms (Opus)

**Impact:** 6 PBE mechanisms currently untestable.

**Files:**
- Modify: `src/pkcs11_check/raw/pack_mechanisms.py`
- Modify: `src/pkcs11_check/testcases/mechanism_helpers.py`
- Modify: `src/pkcs11_check/testcases/mechanism_registry/_legacy.py`

- [ ] **Step 1:** Check `types_std.py` for CK_PBE_PARAMS struct:
```bash
uv run python -c "from pkcs11_check.raw.types_std import CK_PBE_PARAMS; print([f[0] for f in CK_PBE_PARAMS._fields_])"
```

- [ ] **Step 2:** Add `mech_pbe()` packer to `pack_mechanisms.py`.

- [ ] **Step 3:** Add "pbe" style to `build_test_params()` with defaults: password=b"test1234", salt=random 8 bytes, iteration=1000.

- [ ] **Step 4:** Update 6 PBE registry entries with `param_recipe=ParamRecipe("pbe")`.

- [ ] **Step 5:** Commit:
```bash
git commit -m 'feat: add CK_PBE_PARAMS packer and PBE mechanism param recipe'
```

---

### Task 6: Verify MAC mechanism param support (Sonnet)

**Impact:** 4 MAC mechanisms (AES_MAC, CDMF_MAC, CDMF_MAC_GENERAL, RC2_MAC).

- [ ] **Step 1:** Check if these are actually advertised by test modules:
```bash
bash local-builds/test.sh softhsm2 -k "test_mech_sign[AES_MAC] or test_mech_sign[CDMF_MAC] or test_mech_sign[RC2_MAC]" -v --no-header 2>&1 | tail -5
```

- [ ] **Step 2:** If they're parametrized and tested, the "not invoked" is a reporting issue (already addressed by Task 3). If they're skipped, check why.

- [ ] **Step 3:** CKM_AES_MAC should work with `param_recipe="none"` (no params needed per spec). If it fails, investigate.

- [ ] **Step 4:** Commit if changes made.

---

## Phase 3: Performance & Infrastructure (Tasks 7-8)

### Task 7: Add CKM_PUB_KEY_FROM_PRIV_KEY test (Sonnet)

**Impact:** 1 mechanism currently untested.

This Kryoptic mechanism derives a public key from a private key. Simple test:
1. Generate EC keypair
2. Call C_DeriveKey with CKM_PUB_KEY_FROM_PRIV_KEY using private key as base
3. Verify derived object is a public key

- [ ] **Step 1:** Add the test to an appropriate existing file (test_mech_derive.py or a new small test).

- [ ] **Step 2:** Test on Kryoptic if available, skip on modules that don't advertise it.

- [ ] **Step 3:** Commit.

---

### Task 8: Update memory file (Sonnet)

**Files:**
- Modify: `/home/user/.claude/projects/-home-user-src-m-pkcs11-check/memory/project_mechanism_tests_progress.md`

- [ ] **Step 1:** Update with final status reflecting all work done in this session:
- All plans executed (1-6 complete, 7 partially done)
- 467 registry entries, 51 vector files, 42 JSON vector files
- 9 typed import helpers
- Performance caches (mechanism, curve, key import)
- ~35,000+ test bug failures fixed total
- CLAUDE.md updated with no-statistics-update rule

- [ ] **Step 2:** Verify MEMORY.md index is up to date.

---

## Phase 4: Verification (Tasks 9-10)

### Task 9: Run full local test suite (Sonnet)

- [ ] **Step 1:** Run mechanism tests:
```bash
bash local-builds/test.sh softhsm2 -k "test_mech_" --no-header 2>&1 | tail -5
```
Document remaining failure count and compare to baseline (was 74, then 36, should be lower now).

- [ ] **Step 2:** Run KAT tests:
```bash
bash local-builds/test.sh softhsm2 -k "test_kat_vector" --no-header 2>&1 | tail -3
```

- [ ] **Step 3:** Run meta-tests:
```bash
uv run python -m pytest tests/ -x -q --no-header --tb=short 2>&1 | tail -5
```

- [ ] **Step 4:** Run full ruff:
```bash
uv run ruff check src/ tests/
```

---

### Task 10: Final Opus review of entire session's work (Opus)

- [ ] **Step 1:** Review all commits on dev since start of session:
```bash
git log --oneline dev --not main | wc -l
```

- [ ] **Step 2:** Verify no regressions, no broken imports, no circular dependencies.

- [ ] **Step 3:** Check that all new code follows CLAUDE.md rules (error handling, PIN handling, etc.).

- [ ] **Step 4:** Document any remaining issues that need attention in a future session.
