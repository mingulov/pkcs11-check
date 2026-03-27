# Master Plan: Mechanism Coverage Tracking + Test Bug Fixes

## Context

Two related tasks:

**A. Mechanism Coverage Tracking** — After a full test run, `coverage.json` should report which PKCS#11 mechanisms were *actually invoked* against the module (not just referenced in source). Includes "stacked" representation for mechanisms with sub-parameters (e.g., `CKM_RSA_PKCS_OAEP[hashAlg=CKM_SHA256,mgf=CKG_MGF1_SHA256]`).

**B. Test Bug Fixes** — Analysis of artifacts from 8 providers (kryoptic, kryoptic-main, kryoptic-fips, nss, nss-main, nss-pqc, softhsm2, softhsm2-main) revealed 15+ test bugs — failures caused by test code issues, not module behavior. Fix these without adding xfail/skip for real failures.

---

## Part A: Mechanism Coverage Tracking

### A1. Top-level mechanism tracking in RawPKCS11

**File:** `src/pkcs11_check/raw/api.py`

- Add `_used_mechanisms: set[int]` attribute (initialized in `__init__`)
- Add `used_mechanisms` property (returns copy)
- Add `reset_used_mechanisms()` method
- In `_call()`: for the 16 mechanism-taking functions, extract `args[1]._obj.mechanism` and add to `_used_mechanisms`

```
_MECHANISM_ARG_FUNCS = {
    "C_EncryptInit", "C_DecryptInit", "C_DigestInit",
    "C_SignInit", "C_VerifyInit", "C_SignRecoverInit", "C_VerifyRecoverInit",
    "C_GenerateKey", "C_GenerateKeyPair",
    "C_WrapKey", "C_UnwrapKey", "C_DeriveKey",
    "C_MessageEncryptInit", "C_MessageDecryptInit",
    "C_MessageSignInit", "C_MessageVerifyInit",
}
```

Verified: `byref()._obj.mechanism` reliably returns the mechanism type from CArgObject.

### A2. Stacked mechanism tracking in PackedMechanism

**File:** `src/pkcs11_check/raw/pack.py`

- Add `sub_mechanisms: dict[str, int] | None = None` field to `PackedMechanism.__init__`
- In `byref()`: if `sub_mechanisms` is set, record `(self.ck.mechanism, self.sub_mechanisms)` to a module-level thread-safe log

```python
# Module-level in pack.py
import threading
_mechanism_detail_lock = threading.Lock()
_mechanism_detail_log: list[tuple[int, dict[str, int]]] = []

def drain_mechanism_details() -> list[tuple[int, dict[str, int]]]:
    """Return and clear all recorded mechanism details."""
    with _mechanism_detail_lock:
        result = list(_mechanism_detail_log)
        _mechanism_detail_log.clear()
        return result
```

### A3. Update 13 packer functions

**File:** `src/pkcs11_check/raw/pack_mechanisms.py`

Each packer passes `sub_mechanisms=` to PackedMechanism:

| Packer | Sub-params |
|--------|-----------|
| `mech_pss()` | `{"hashAlg": hash_mech, "mgf": mgf}` |
| `mech_oaep()` | `{"hashAlg": hash_mech, "mgf": mgf}` |
| `mech_ecdh()` | `{"kdf": kdf}` |
| `mech_hkdf()` | `{"prfHashMechanism": hash_mech}` |
| `mech_pbkdf2()` | `{"prf": prf}` |
| `mech_tls12_master_key_derive()` | `{"prfHashMechanism": hash_mech}` |
| `mech_tls12_key_mat()` | `{"prfHashMechanism": hash_mech}` |
| `mech_tls12_extended_master_key_derive()` | `{"prfHashMechanism": hash_mech}` |
| `mech_tls_kdf()` | `{"prfMechanism": prf_mechanism}` |
| `mech_tls_mac()` | `{"prfHashMechanism": prf_hash_mechanism}` |
| `mech_wtls_master_key_derive()` | `{"DigestMechanism": digest_mechanism}` |
| `mech_wtls_key_mat()` | `{"DigestMechanism": digest_mechanism}` |
| `mech_wtls_prf()` | `{"DigestMechanism": digest_mechanism}` |

### A4. Plugin aggregation

**File:** `src/pkcs11_check/plugin.py`

- Add stash key `_CUMULATIVE_USED_MECHANISMS: pytest.StashKey[set[int]]`
- Add stash key `_CUMULATIVE_MECHANISM_DETAILS: pytest.StashKey[set[tuple[int, frozenset[tuple[str, int]]]]]`
- Initialize both in `pytest_configure`
- In `pytest_runtest_teardown`: collect `rs.raw.used_mechanisms` → `_CUMULATIVE_USED_MECHANISMS`; collect `drain_mechanism_details()` → `_CUMULATIVE_MECHANISM_DETAILS`
- In `pytest_sessionfinish`: build `mechanism_coverage` dict with `available`, `invoked`, `not_invoked`, `invocations_detail` (stacked strings)
- Write a `$report_type: "CoverageReport"` JSONL entry to the report log so isolated runner can merge

### A5. Coverage.json generation in file_runner

**File:** `src/pkcs11_check/core/file_runner.py`

- After `write_report_jsonl()`, parse all `CoverageReport` JSONL entries
- Merge `invoked` sets and `detail` sets across units
- Write `coverage.json` alongside `results.json`
- Also embed in `results.json` via existing `coverage` parameter

**File:** `src/pkcs11_check/cli/test_cmd.py`

- For `--isolation none` path: read stash `_COVERAGE_DATA` from the pytest session config (in-process, so accessible) and write `coverage.json`

### A6. Output format

```json
{
  "mechanisms_available": ["CKM_AES_CBC", "CKM_AES_ECB", ...],
  "mechanisms_invoked": ["CKM_AES_CBC", "CKM_AES_ECB", ...],
  "mechanisms_not_invoked": ["CKM_ARIA_KEY_GEN", ...],
  "invocations_detail": [
    "CKM_AES_CBC",
    "CKM_AES_ECB",
    "CKM_RSA_PKCS_OAEP[hashAlg=CKM_SHA_1,mgf=CKG_MGF1_SHA1]",
    "CKM_RSA_PKCS_OAEP[hashAlg=CKM_SHA256,mgf=CKG_MGF1_SHA256]",
    "CKM_ECDH1_DERIVE[kdf=CKD_NULL]",
    "CKM_HKDF_DERIVE[prfHashMechanism=CKM_SHA256]"
  ],
  "functions_available": ["C_Initialize", ...],
  "functions_called": ["C_Initialize", ...],
  "functions_not_called": ["C_WaitForSlotEvent", ...]
}
```

---

## Part B: Test Bug Fixes

Ordered by severity (most tests affected first). Rules: fix test logic only, never suppress real module failures.

### B1. Key usage flags missing (45+ tests across 6 providers)

**Root cause:** `gen_aes_key()`, `gen_rsa_keypair()`, etc. in recipes.py don't include operation-specific attributes (CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP, CKA_DERIVE). SoftHSM2 is permissive, Kryoptic/NSS enforce spec.

**Fix:** Update default attributes in recipe helper functions or in the affected tests' key generation calls to include the needed usage flags. Many tests already have a pattern for this — follow existing convention.

**Files:** Multiple test files (`test_sign.py`, `test_crossverify.py`, `test_interop.py`, `test_errors.py`, `test_multipart.py`, etc.) + possibly `src/pkcs11_check/raw/recipes.py` if changing defaults.

### B2. test_sensitivity.py — wrong assertion logic (ALL providers)

**Root cause:** Tests assert "Module allowed reading CKA_VALUE on sensitive key" as failure. But PKCS#11 spec says `C_GetAttributeValue` returns CKR_ATTRIBUTE_SENSITIVE with the attribute value zeroed/empty — the call itself doesn't fail, the value is just unusable. The test checks the wrong condition.

**Fix:** Check that the returned value is empty/zeroed (compliant behavior) rather than asserting the call must fail.

**File:** `src/pkcs11_check/testcases/test_sensitivity.py`

### B3. test_remaining_gaps.py — KeyError on template attributes (ALL providers)

**Root cause:** `read_attributes()` doesn't handle `CKA_WRAP_TEMPLATE`, `CKA_UNWRAP_TEMPLATE`, `CKA_DERIVE_TEMPLATE` (array/template-type attributes).

**Fix:** Either update `read_attributes()` to handle template-type attributes, or use direct `C_GetAttributeValue` calls in the test for these specific attributes.

**File:** `src/pkcs11_check/testcases/test_remaining_gaps.py` (and possibly `src/pkcs11_check/raw/recipes.py`)

### B4. test_attribute_enforcement.py — KeyError on CKA_CHECK_VALUE (6/8 providers)

**Root cause:** `read_attributes()` default attribute list doesn't include `CKA_CHECK_VALUE`.

**Fix:** Request `CKA_CHECK_VALUE` explicitly when reading attributes in these tests.

**File:** `src/pkcs11_check/testcases/test_attribute_enforcement.py`

### B5. test_v30_session.py — RawSession missing `config` attribute (6/8 providers)

**Root cause:** Tests access `rs.config` but `RawSession` dataclass has no `config` field. Need `p11_config` fixture.

**Fix:** Add `p11_config` fixture parameter to the test functions and use it instead of `rs.config`.

**File:** `src/pkcs11_check/testcases/test_v30_session.py`

### B6. test_extended_mechanisms.py — hashlib + wrong expected value (3/8 providers)

**Root cause:** (a) `hashlib.sha512_224` doesn't exist in Python < 3.12. (b) SHA-512/256 test compares against SHA-256 expected value (wrong constant).

**Fix:** (a) Guard with `sys.version_info >= (3, 12)` or catch AttributeError. (b) Fix the expected digest constant.

**File:** `src/pkcs11_check/testcases/test_extended_mechanisms.py`

### B7. test_sign_recover.py — missing capability check (ALL providers)

**Root cause:** Tests call `C_SignRecoverInit`/`C_VerifyRecoverInit` without checking if the module supports sign/verify recover functions.

**Fix:** Add `has_mechanism` + function availability check, skip if not supported.

**File:** `src/pkcs11_check/testcases/test_sign_recover.py`

### B8. test_eddsa.py — CKR_DEVICE_ERROR on all providers

**Root cause:** EdDSA parameter setup issue. Need to investigate the exact CK_EDDSA_PARAMS or mechanism type used.

**Fix:** Investigate and fix parameter construction. May need `mech_eddsa()` packer with correct params.

**File:** `src/pkcs11_check/testcases/test_eddsa.py`

### B9. test_message_crypto.py — missing v3.0 capability check

**Root cause:** Message API functions (`C_MessageEncryptInit` etc.) not checked for availability. Most modules don't support them.

**Fix:** Add function availability check (v3.0 feature), skip if not supported.

**File:** `src/pkcs11_check/testcases/test_message_crypto.py`

### B10. test_ecdh_extended.py — X25519 DER parsing

**Root cause:** Test expects DER OCTET STRING (tag 0x04) wrapping the public key, but module returns raw key bytes starting with 0xc1.

**Fix:** Handle both DER-wrapped and raw public key formats.

**File:** `src/pkcs11_check/testcases/test_ecdh_extended.py`

### B11. test_operation_state.py — subprocess output parsing

**Root cause:** Test parses subprocess stdout for `CROSS_SESSION_ACCEPTED` / `CROSS_SESSION_REJECTED` using dict-based matching that misses the output.

**Fix:** Fix the parsing logic to correctly extract the status from subprocess output.

**File:** `src/pkcs11_check/testcases/test_operation_state.py`

---

## Execution Order

1. **Part A (mechanism coverage):** A1 → A2 → A3 → A4 → A5 → A6
2. **Part B (test fixes):** B1 → B2 → B3 → B4 → B5 → B6 → B7 → B8 → B9 → B10 → B11

Parts A and B are independent and can be worked in parallel.

## Verification

- **Part A:** Run `bash local-builds/test.sh softhsm2 -m smoke` — verify `coverage.json` appears with `mechanisms_invoked` containing real mechanism names. Run `bash docker/test.sh kryoptic -- src/pkcs11_check/testcases/test_encrypt.py -v` — verify stacked entries like `CKM_RSA_PKCS_OAEP[...]` appear in detail.
- **Part B:** For each fix, run the affected test against at least 2 providers (softhsm2 + kryoptic or nss). Verify the failure count drops. Run full `bash local-builds/test.sh softhsm2` to confirm no regressions. Run `uv run python -m pytest tests/ -x -q` for meta-test regressions.
- **Final:** Run `bash docker/test.sh kryoptic` and compare `artifacts/kryoptic/results.json` failure count against current baseline (198 failures). Expect significant reduction.
