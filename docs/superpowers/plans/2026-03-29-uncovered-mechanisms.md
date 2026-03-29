# Uncovered Mechanisms Fix Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Use **Sonnet 4.6** for implementation, **Opus 4.6** for investigation.

**Goal:** Fix mechanism coverage gaps so that all module-advertised mechanisms are properly tested. Currently ~35 mechanisms show as "not invoked" despite being in the registry.

**Architecture:** 5 tasks: fix missing keygen_mech entries, fix coverage counter alias tracking, add PBE param packer, verify DES encrypt-data derive, and add MAC param recipes.

**Tech Stack:** Python 3.11+, pytest, pkcs11_check.raw

---

## Analysis of "not invoked" mechanisms

| Category | Count | Root Cause | Action |
|----------|-------|-----------|--------|
| Alias (CKM_ECDSA_KEY_PAIR_GEN = CKM_EC_KEY_PAIR_GEN) | 1 | Coverage counter tracks name, not ID | Task 1 |
| Missing keygen_mech (MD2/MD5 RSA/HMAC) | 5 | keygen_mech=None in registry, keygen skips | Task 2 |
| SHA*_KEY_GEN (14 entries) | 14 | These ARE keygen mechanisms, used internally | Not a gap |
| DES*_ENCRYPT_DATA (4 entries) | 4 | Derive mechanisms with string_data recipe | Task 3 |
| MAC mechanisms (AES_MAC, CDMF_MAC, RC2_MAC) | 4 | May need MAC param or module doesn't advertise | Task 4 |
| PBE mechanisms (6 entries) | 6 | Need CK_PBE_PARAMS packer | Task 5 |
| CKM_PUB_KEY_FROM_PRIV_KEY | 1 | Kryoptic-specific, needs dedicated test | Task 5 |
| CKM_SHA3_*_KEY_DERIVATION (4 entries) | 4 | Not in MECHANISM_NAMES -- Kryoptic uses non-standard names | Module quirk, not fixable |

---

### Task 1: Fix coverage counter for mechanism aliases (Sonnet)

**Impact:** CKM_ECDSA_KEY_PAIR_GEN (0x1040) IS invoked but tracked under the name CKM_EC_KEY_PAIR_GEN.

**Files:**
- Modify: `src/pkcs11_check/compliance_report.py` -- find the mechanism coverage tracking
- Or: `src/pkcs11_check/raw/api.py` -- find where used_mechanisms are tracked

- [ ] **Step 1:** Read how mechanism invocation is tracked. Search for `used_mechanisms`, `invoked_mechanisms`, or `mechanism_coverage` in the codebase.

- [ ] **Step 2:** The tracking should resolve aliases -- if CKM_EC_KEY_PAIR_GEN (0x1040) is invoked, CKM_ECDSA_KEY_PAIR_GEN (same ID 0x1040) should also be marked as invoked.

- [ ] **Step 3:** Fix the tracking to group by mechanism ID, not just name. When reporting "not invoked", check if ANY alias for the same ID was invoked.

- [ ] **Step 4:** Commit:
```bash
git commit -m 'fix: track mechanism coverage by ID to handle aliases like CKM_ECDSA_KEY_PAIR_GEN'
```

---

### Task 2: Add missing keygen_mech to legacy sign mechanisms (Sonnet)

**Impact:** 5 mechanisms have keygen_mech=None which causes the mechanism-driven sign/keygen tests to skip.

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_registry/_rsa.py`
- Modify: `src/pkcs11_check/testcases/mechanism_registry/_hmac.py` or `_misc.py`

- [ ] **Step 1:** Find and fix these entries:

| Mechanism | Current keygen_mech | Fix |
|-----------|-------------------|-----|
| CKM_MD2_RSA_PKCS | None | `CKM_RSA_PKCS_KEY_PAIR_GEN` |
| CKM_MD5_RSA_PKCS | None | `CKM_RSA_PKCS_KEY_PAIR_GEN` |
| CKM_MD2_HMAC | None | `CKM_GENERIC_SECRET_KEY_GEN` |
| CKM_MD2_HMAC_GENERAL | None | `CKM_GENERIC_SECRET_KEY_GEN` |
| CKM_MD5_HMAC_GENERAL | None | `CKM_GENERIC_SECRET_KEY_GEN` |

For RSA entries, also set `is_keypair=True, key_type=CKK_RSA, key_sizes=(2048, 4096)`.
For HMAC entries, set `key_type=CKK_GENERIC_SECRET` (or the specific HMAC key type).

- [ ] **Step 2:** Lint and test:
```bash
bash local-builds/test.sh softhsm2 -k "test_mech_sign[MD5_RSA_PKCS]" -v --no-header
```

- [ ] **Step 3:** Commit:
```bash
git commit -m 'fix: add keygen_mech to MD2/MD5 RSA and HMAC registry entries'
```

---

### Task 3: Verify DES encrypt-data derive mechanisms work (Opus investigation)

**Impact:** 4 mechanisms: CKM_DES_ECB_ENCRYPT_DATA, CKM_DES_CBC_ENCRYPT_DATA, CKM_DES3_ECB_ENCRYPT_DATA, CKM_DES3_CBC_ENCRYPT_DATA.

These have `param_recipe=ParamRecipe("string_data")` and `expected_flags=CKF_DERIVE`. The derive test should parametrize them via `mech_derive_entry`.

**Files:**
- Read: `src/pkcs11_check/testcases/test_mech_derive.py` -- check if string_data derive is handled

- [ ] **Step 1:** Check if `_derive_aes_ecb()` or a similar helper handles CKM_DES*_ENCRYPT_DATA. These mechanisms derive a key by encrypting data with an existing key.

- [ ] **Step 2:** If the derive test handles AES_ECB_ENCRYPT_DATA but not DES variants, the issue may be that the DES variants need a DES base key (not AES). Check the dispatch.

- [ ] **Step 3:** If a fix is needed, add DES base key generation to the derive helper. If the test already handles it but the module doesn't support the mechanism, document as module finding.

- [ ] **Step 4:** Commit if changes made.

---

### Task 4: Add MAC mechanism param support (Sonnet)

**Impact:** CKM_AES_MAC, CKM_CDMF_MAC, CKM_CDMF_MAC_GENERAL, CKM_RC2_MAC -- 4 mechanisms.

These are sign mechanisms (CKF_SIGN) that should be picked up by mech_sign_entry. Check why they aren't invoked:
- Module may not advertise them
- Or param_recipe="none" but they need a param (MAC_GENERAL needs CK_MAC_GENERAL_PARAMS = a CK_ULONG for output length)

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_registry/_aes.py`, `_des.py`, `_legacy.py` if needed

- [ ] **Step 1:** Check if CKM_AES_MAC needs a parameter. Per PKCS#11 spec, CKM_AES_MAC requires no parameter (output is always full block). CKM_AES_MAC_GENERAL needs CK_MAC_GENERAL_PARAMS.

- [ ] **Step 2:** These should already work with the mechanism-driven sign tests if the module advertises them. Check if the registry `param_recipe` is correct (should be "none" for AES_MAC, "mac_general" for AES_MAC_GENERAL).

- [ ] **Step 3:** The "not invoked" may simply mean the modules tested don't advertise these mechanisms. Check:
```bash
bash local-builds/test.sh softhsm2 -k "test_mech_sign[AES_MAC]" -v --no-header
```
If it's collected and parametrized, the mechanism IS tested.

- [ ] **Step 4:** Commit if changes made.

---

### Task 5: Add CK_PBE_PARAMS packer for PBE mechanisms (Opus)

**Impact:** 6 PBE mechanisms: CKM_PBE_MD2_DES_CBC, CKM_PBE_MD5_DES_CBC, CKM_PBE_SHA1_RC2_128_CBC, CKM_PBE_SHA1_RC2_40_CBC, CKM_PBE_SHA1_RC4_128, CKM_PBE_SHA1_RC4_40.

These are key generation mechanisms that derive keys from passwords. They need CK_PBE_PARAMS (password, salt, iteration count).

**Files:**
- Modify: `src/pkcs11_check/raw/pack_mechanisms.py` -- add `mech_pbe()`
- Modify: `src/pkcs11_check/testcases/mechanism_helpers.py` -- add "pbe" style to `build_test_params()`
- Modify: `src/pkcs11_check/testcases/mechanism_registry/_legacy.py` -- update PBE entries

- [ ] **Step 1:** Check `types_std.py` for CK_PBE_PARAMS struct definition.

- [ ] **Step 2:** Add packer:
```python
def mech_pbe(mechanism_type: CKM, *, password: bytes, salt: bytes, iteration: int) -> PackedMechanism:
    """Pack CK_PBE_PARAMS."""
    ...
```

- [ ] **Step 3:** Add "pbe" style to `build_test_params()` with default password=b"test1234", salt=random 8 bytes, iteration=1000.

- [ ] **Step 4:** Update registry entries with `param_recipe=ParamRecipe("pbe")`.

- [ ] **Step 5:** Also handle CKM_PUB_KEY_FROM_PRIV_KEY -- this is a derive mechanism that takes no params but needs an EC private key as the base key. Add a note in the registry or a simple test.

- [ ] **Step 6:** Commit:
```bash
git commit -m 'feat: add CK_PBE_PARAMS packer and PBE mechanism param recipe'
```
