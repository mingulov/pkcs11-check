# Docker Artifact Failure Analysis Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Use **Opus 4.6** for analysis tasks, **Sonnet 4.6** for fix implementation.

**Goal:** Analyze all mechanism test failures across 4 Docker providers, separate test bugs from module findings, fix test bugs, and document module findings.

**Architecture:** 3 phases: (1) Fix test bugs that cause false failures across multiple providers, (2) Fix registry data errors (expected_flags), (3) Triage remaining failures as module findings. Artifacts are in `/home/user/src/m/pkcs11-check/artifacts2/`.

**Tech Stack:** Python 3.11+, pytest, pkcs11_check.raw

**Providers analyzed:** softhsm2-main (74 mech fails), kryoptic-main (229), nss-pqc (77), opencryptoki-master (144) = **524 total mech test failures**

---

## Failure Summary

| Category | Count | Root cause | Action |
|----------|-------|-----------|--------|
| HMAC keygen TEMPLATE_INCONSISTENT | **147** | Test uses HMAC mechanism for keygen instead of GENERIC_SECRET_KEY_GEN | **Fix (Task 1)** |
| Expected flags mismatch | 21 | Registry expected_flags don't match actual modules | **Fix (Task 2)** |
| Wrap test TEMPLATE_INCOMPLETE | 33 | Wrap tests create keys without proper wrap/unwrap attrs | **Fix (Task 3)** |
| NSS keygen `assert False is True` | 26 | NSS `test_local_flag` assertion fails for keygen mechs | **Investigate (Task 4)** |
| Derive TEMPLATE_INCONSISTENT | ~14 | Derive base key templates wrong (HKDF, SHA-KDF) | **Fix (Task 5)** |
| Kryoptic CKR_DEVICE_ERROR sign/verify | 31 | Known Kryoptic bug — sign/verify fails with DEVICE_ERROR | **Document (Task 6)** |
| EC curve unsupported | 31 | EdDSA/Montgomery curves not supported by provider | **Module finding** |
| CKR_MECHANISM_INVALID | ~50 | Module advertises but rejects mechanism | **Module finding** |
| Other provider-specific | ~170 | Various module quirks | **Triage (Task 6)** |

---

## Phase 1: Fix Test Bugs (Tasks 1-5)

### Task 1: Fix HMAC keygen — use CKM_GENERIC_SECRET_KEY_GEN

**Impact:** Fixes **147 failures** across all 4 providers.

**Root cause:** All HMAC mechanisms (SHA-1/224/256/384/512 + SHA3 variants + GENERAL variants) fail `C_GenerateKey` with `CKR_TEMPLATE_INCONSISTENT`. The test uses the HMAC mechanism itself (e.g., `CKM_SHA256_HMAC`) as the keygen mechanism — but HMAC mechanisms are NOT keygen mechanisms. The correct keygen is `CKM_GENERIC_SECRET_KEY_GEN`.

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_helpers.py` — `generate_key_from_recipe()` symmetric keygen path
- Possibly modify: `src/pkcs11_check/testcases/mechanism_registry/_hmac.py` — verify `keygen_mech` is set correctly

- [ ] **Step 1:** Check what `keygen_mech` is set to for HMAC entries in the registry:
```bash
uv run python -c "
from pkcs11_check.testcases.mechanism_registry import MECHANISM_REGISTRY
from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
for mid, cfg in MECHANISM_REGISTRY.items():
    mname = MECHANISM_NAMES.get(mid, '')
    if 'HMAC' in mname and cfg.keygen_mech is not None:
        print(f'{mname}: keygen_mech=0x{int(cfg.keygen_mech):08x}')
        break
"
```

- [ ] **Step 2:** Read `src/pkcs11_check/testcases/mechanism_helpers.py` — find `generate_key_from_recipe()` and trace what happens for HMAC mechanisms. The `keygen_recipe.style` for HMAC is `"generic"` (not `"symmetric"`). Check if the `"generic"` path uses `CKM_GENERIC_SECRET_KEY_GEN` correctly.

- [ ] **Step 3:** Fix the issue. The most likely fixes:
- If `keygen_mech` in registry is wrong (points to HMAC mechanism instead of GENERIC_SECRET_KEY_GEN), fix the registry
- If `generate_key_from_recipe()` uses `config.keygen_mech` which is the HMAC mechanism, add a fallback to `CKM_GENERIC_SECRET_KEY_GEN` for `"generic"` style keys
- HMAC keys need `CKK_GENERIC_SECRET` key type and `CKA_VALUE_LEN` set to the hash output size

- [ ] **Step 4:** Test locally:
```bash
bash local-builds/test.sh softhsm2 -k "test_mech_encrypt[SHA256_HMAC] or test_mech_sign[SHA256_HMAC] or test_mech_keygen[SHA256_HMAC]" -v
```

- [ ] **Step 5:** Test across more HMAC variants:
```bash
bash local-builds/test.sh softhsm2 -k "HMAC" --no-header 2>&1 | tail -5
```

- [ ] **Step 6:** Commit:
```bash
git commit -m 'fix: use CKM_GENERIC_SECRET_KEY_GEN for HMAC key generation'
```

---

### Task 2: Fix expected_flags mismatches in registry

**Impact:** Fixes **21 failures** across 3 providers.

**Root cause:** The registry's `expected_flags` field has incorrect flags for certain mechanisms. Examples:
- AES-CBC/ECB/GCM on SoftHSM2: missing `CKF_WRAP`/`CKF_UNWRAP` in actual flags but expected in registry
- AES-CFB/OFB on Kryoptic: same
- RSA-PKCS/X509 on SoftHSM2+Kryoptic: flag mismatches

The `expected_flags` should reflect what the OASIS spec REQUIRES, not what any single module reports. If the spec says a mechanism MAY support wrap/unwrap but the module doesn't, that's not a failure.

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_flags.py` — change the assertion to be less strict, OR
- Modify: Registry `_aes.py`, `_des.py`, `_rsa.py`, `_ciphers.py` — adjust expected_flags

- [ ] **Step 1:** Read `src/pkcs11_check/testcases/test_mech_flags.py` — understand what `test_expected_flags_present` checks.

- [ ] **Step 2:** Read the OASIS spec for AES mechanisms at `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/aes.md` — check what flags are REQUIRED vs OPTIONAL for AES-CBC, AES-ECB, AES-GCM.

- [ ] **Step 3:** Decide the approach:
  - **Option A:** Change `expected_flags` to only include REQUIRED flags (CKF_ENCRYPT|CKF_DECRYPT for AES ciphers) and remove OPTIONAL ones (CKF_WRAP|CKF_UNWRAP)
  - **Option B:** Change the test to distinguish required vs optional flags

Option A is simpler and correct. The spec says CKF_WRAP/UNWRAP are optional for most ciphers.

- [ ] **Step 4:** Update the registry entries with corrected flags.

- [ ] **Step 5:** Commit:
```bash
git commit -m 'fix: correct expected_flags in registry to match OASIS spec requirements'
```

---

### Task 3: Fix wrap test TEMPLATE_INCOMPLETE failures

**Impact:** Fixes **33 failures** across 3 providers.

**Root cause:** `test_mech_wrap.py` creates keys without proper wrapping attributes. The wrap test needs keys with `CKA_WRAP=True` on the wrapping key and `CKA_EXTRACTABLE=True` on the key being wrapped.

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_wrap.py`

- [ ] **Step 1:** Read `src/pkcs11_check/testcases/test_mech_wrap.py` — find the wrap/unwrap test and check what attributes are set on generated keys.

- [ ] **Step 2:** Check the specific `longrepr` from artifacts:
```bash
python3 -c "
import json
d=json.load(open('/home/user/src/m/pkcs11-check/artifacts2/softhsm2-main/results.json'))
for u in d['units']:
    if 'test_mech_wrap' in u.get('target',''):
        for t in u.get('tests',[]):
            if t.get('outcome')=='failed':
                print(f'{t[\"nodeid\"].split(\"::\")[-1]}')
                print(f'  {t[\"longrepr\"][:200]}')
                print()
"
```

- [ ] **Step 3:** Fix the key generation templates to include proper wrap/unwrap/extractable attributes.

- [ ] **Step 4:** Commit:
```bash
git commit -m 'fix: add proper wrap/unwrap attributes to test_mech_wrap key templates'
```

---

### Task 4: Investigate NSS keygen `assert False is True` failures

**Impact:** Affects **26 failures** on NSS-PQC only.

**Root cause:** `test_mech_keygen.py::TestMechKeygen::test_local_flag` fails for ALL keygen mechanisms on NSS. The `assert False is True` suggests `CKA_LOCAL` is not set on generated keys — this is a known NSS spec deviation.

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_keygen.py` — possibly xfail for NSS, or adjust test

- [ ] **Step 1:** Read `test_mech_keygen.py` — find `test_local_flag`, understand what it checks.

- [ ] **Step 2:** Check the OASIS spec: is `CKA_LOCAL` required to be True for generated keys?
Read: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/` — search for CKA_LOCAL.

- [ ] **Step 3:** If CKA_LOCAL is spec-required: this is a real NSS finding. The test should remain as-is and the finding should be documented.
If CKA_LOCAL is optional: the test should check but not fail (use compliance.note instead).

- [ ] **Step 4:** Based on analysis, either document as finding or adjust test.

- [ ] **Step 5:** Commit if changes made.

---

### Task 5: Fix derive base key TEMPLATE_INCONSISTENT

**Impact:** Fixes **~14 failures** on Kryoptic.

**Root cause:** HKDF_DERIVE and SHA*_KEY_DERIVATION mechanisms fail because the derive base key template is wrong. The `_derive_hkdf` helper in `test_mech_derive.py` creates a base key with incorrect attributes.

**Files:**
- Modify: `src/pkcs11_check/testcases/test_mech_derive.py` — `_derive_hkdf()` and `_derive_sha()` helpers

- [ ] **Step 1:** Read the specific failure from artifacts:
```bash
python3 -c "
import json
d=json.load(open('/home/user/src/m/pkcs11-check/artifacts2/kryoptic-main/results.json'))
for u in d['units']:
    if 'test_mech_derive' in u.get('target',''):
        for t in u.get('tests',[]):
            if t.get('outcome')=='failed':
                print(t['nodeid'].split('::')[-1])
                print(f'  {t[\"longrepr\"][:300]}')
                print()
" | head -40
```

- [ ] **Step 2:** Read `test_mech_derive.py` — find `_derive_hkdf()` and `_gen_hkdf_base_key()`. Check what key type and attributes are used.

- [ ] **Step 3:** Read the OASIS HKDF spec at `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/` — check what base key type is required for HKDF. It likely needs `CKK_HKDF` or `CKK_GENERIC_SECRET` with `CKA_DERIVE=True`.

- [ ] **Step 4:** Fix the base key template. Common issues:
- Missing `CKA_DERIVE=True` on base key
- Wrong key type (should be `CKK_GENERIC_SECRET` or `CKK_HKDF`)
- Missing `CKA_VALUE_LEN` for generic secret
- Using wrong keygen mechanism

- [ ] **Step 5:** Test and commit.

---

## Phase 2: Triage Module Findings (Task 6)

### Task 6: Categorize remaining failures as module findings

**Goal:** After fixing test bugs (Tasks 1-5), re-examine remaining failures and document them.

- [ ] **Step 1:** After Tasks 1-5 are committed, run a fresh Docker test on one provider to see how many failures remain:
```bash
bash docker/test.sh softhsm2-main -- src/pkcs11_check/testcases/test_mech_flags.py src/pkcs11_check/testcases/test_mech_keygen.py src/pkcs11_check/testcases/test_mech_encrypt.py src/pkcs11_check/testcases/test_mech_sign.py src/pkcs11_check/testcases/test_mech_derive.py src/pkcs11_check/testcases/test_mech_wrap.py
```

- [ ] **Step 2:** For remaining failures, categorize into:
  - **Module bug** — module returns wrong CKR code (document in `docs/module-issues.md`)
  - **Spec deviation** — module doesn't implement spec requirement (document)
  - **Test bug** — our test has wrong expectations (fix)
  - **Missing capability** — should be a skip, not a fail (fix test to check first)

Categories of remaining failures expected to be module findings:
- `CKR_DEVICE_ERROR` on Kryoptic sign/verify (31) — known Kryoptic bug
- `CKR_CURVE_NOT_SUPPORTED` (31) — EdDSA/Montgomery not supported
- `CKR_MECHANISM_INVALID` for HASH_ML_DSA/SLH_DSA on Kryoptic (30+) — PQC hash mechanisms not implemented
- `CKR_MECHANISM_INVALID` for DES on SoftHSM2 (8+) — deprecated DES removed
- `CKR_KEY_TYPE_INCONSISTENT` on various (17) — wrong key type for mechanism
- `CKR_MECHANISM_PARAM_INVALID` on various (24) — param handling differences

- [ ] **Step 3:** Update `docs/module-issues.md` with new findings.

- [ ] **Step 4:** For failures that should be skips (e.g., mechanism advertised but param handling unsupported), add appropriate guards in test code.

- [ ] **Step 5:** Commit all changes:
```bash
git commit -m 'docs: document module findings from Docker artifact analysis'
```

---

## Phase 3: Verification (Task 7)

### Task 7: Re-run Docker tests and verify improvement

- [ ] **Step 1:** Run fresh Docker tests on all 4 providers (targeted at mech tests):
```bash
bash docker/test.sh softhsm2-main
bash docker/test.sh kryoptic-main
```

- [ ] **Step 2:** Compare failure counts to baseline:

| Provider | Before | After | Improvement |
|----------|--------|-------|-------------|
| softhsm2-main | 74 | ? | ? |
| kryoptic-main | 229 | ? | ? |
| nss-pqc | 77 | ? | ? |
| opencryptoki-master | 144 | ? | ? |

- [ ] **Step 3:** Update `docs/module-matrix.md` with new Docker results.

- [ ] **Step 4:** Final commit.
