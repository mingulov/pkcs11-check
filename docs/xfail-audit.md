# xfail/skip Audit Report

**Date:** 2026-03-27
**Scope:** `src/pkcs11_check/testcases/` (including `ckr/` and `wycheproof/` subdirectories)

## Summary

| Metric | Count |
|--------|-------|
| Total `pytest.xfail()` calls | 285 |
| Converted to `pytest.skip()` | 25 |
| Correct xfails (kept) | 226 |
| Unclear / needs human review | 34 |

## Categorization Criteria

Per AGENTS.md:
- **skip**: missing capabilities (mechanism not advertised, object type not enumerated, function not in list)
- **xfail**: known module bugs, CVE regressions, security failures, valid-vector rejections

### Converted to `pytest.skip()` (25 calls)

These are clearly missing-capability cases where the module does not implement a feature.

#### Object type enumeration (11 calls)

| File | Line | Reason |
|------|------|--------|
| `test_profiles.py` | 49 | `Module does not support CKO_PROFILE enumeration` |
| `test_trust_objects.py` | 50 | `Module does not support CKO_TRUST enumeration` |
| `test_validation_objects.py` | 59 | `Module does not support CKO_VALIDATION enumeration` |
| `test_mechanism_objects.py` | 41 | `Module does not support CKO_MECHANISM enumeration` |
| `test_mechanism_objects.py` | 51 | `Module does not support CKO_MECHANISM enumeration` |
| `test_mechanism_objects.py` | 71 | `Module does not support CKO_MECHANISM enumeration` |
| `test_mechanism_objects.py` | 98 | `Module does not support CKO_MECHANISM enumeration` |
| `test_hw_features.py` | 58 | `Module does not support CKO_HW_FEATURE enumeration` |
| `test_hw_features.py` | 125 | `Module does not support CKO_HW_FEATURE enumeration` |
| `test_hw_features.py` | 179 | `Module does not support CKO_HW_FEATURE enumeration` |
| `test_domain_params.py` | 176 | `Module does not support CKO_DOMAIN_PARAMETERS enumeration` |
| `test_domain_params.py` | 186 | `Module does not support CKO_DOMAIN_PARAMETERS enumeration` |

#### v3.0 function availability (8 calls)

| File | Line | Reason |
|------|------|--------|
| `test_v30_session.py` | 286 | `Module does not implement CKU_CONTEXT_SPECIFIC login` |
| `test_v30_session.py` | 329 | `Module does not implement C_LoginUser` |
| `test_v30_session.py` | 382 | `Module does not implement C_LoginUser (not in function list)` |
| `test_v30_session.py` | 394 | `Module does not implement C_LoginUser (CKR_FUNCTION_NOT_SUPPORTED)` |
| `test_v30_session.py` | 418 | `Module does not implement C_LoginUser (not in function list)` |
| `test_v30_session.py` | 440 | `Module does not implement C_LoginUser (CKR_FUNCTION_NOT_SUPPORTED)` |
| `test_v30_session.py` | 718 | `Module does not support non-empty username for C_LoginUser` |

#### PQC / KDF mechanism support (6 calls)

| File | Line | Reason |
|------|------|--------|
| `test_pqc_sign.py` | 155 | `Module does not support CKA_PARAMETER_SET=...` |
| `test_pqc_sign.py` | 284 | `Module does not support CKA_PARAMETER_SET=...` |
| `test_kem.py` | 168 | `Module does not expose ML-KEM public key value` |
| `test_kem.py` | 376 | `Module does not support direct AES key derivation via encapsulation` |
| `test_kem.py` | 408 | `Module does not support direct AES key derivation via encapsulation` |
| `test_hkdf_extended.py` | 190 | `CKM_HKDF_KEY_GEN with key_type=... not supported` |

## Correct xfails (226 calls)

These are legitimate xfail uses covering:
- **Module bugs**: Kryoptic CKR_DEVICE_ERROR on verify (3), TPM2 CKA_DERIVE rejection (1)
- **Security issues**: CKA_EXTRACTABLE escalation, CKA_SENSITIVE downgrade (4)
- **Crash detection**: subprocess segfaults (5)
- **Valid vector rejections**: Wycheproof/ACVP accepted vectors the module rejects (~90)
- **Spec violations**: accepted CKU_CONTEXT_SPECIFIC without active operation (2), non-conformant C_SessionCancel (3)
- **Operational failures on attempted mechanisms**: SSL3, TLS12, WTLS, IKE, SP800_108, RSA_X9_31, PBE, misc KDF, etc. (~80)
- **Stateful sig issues**: CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID (3)
- **Behavioral issues**: deterministic ML-DSA signatures (1), RSA-OAEP param mismatch (3)

## Unclear / needs human review (34 calls)

These cases are ambiguous - the module attempts the operation but fails, and it is unclear whether this is a missing capability or a bug.

### "Cannot read attribute" after successful enumeration (10 calls)

| File | Line | Reason |
|------|------|--------|
| `test_trust_objects.py` | 75 | `Cannot read CKA_ISSUER from trust object` |
| `test_trust_objects.py` | 91 | `Cannot read CKA_SERIAL_NUMBER from trust object` |
| `test_validation_objects.py` | 84 | `Cannot read CKA_VALIDATION_TYPE from validation object` |
| `test_validation_objects.py` | 102 | `Cannot read CKA_VALIDATION_LEVEL from validation object` |
| `test_hw_features.py` | 83 | `Cannot read CKA_HW_FEATURE_TYPE` |
| `test_hw_features.py` | 228 | `Cannot read reset attrs from counter` |
| `test_mechanism_objects.py` | 60 | `Cannot read CKA_MECHANISM_TYPE from mechanism object` |
| `test_profiles.py` | 77 | `Cannot read CKA_PROFILE_ID` |
| `test_domain_params.py` | 161 | `Module does not expose CKA_LOCAL on domain params` |
| `test_domain_params.py` | 195 | `Cannot read CKA_KEY_TYPE from domain parameter object` |

**Rationale:** The object was successfully enumerated, but an attribute read fails. This could be a partial implementation (skip) or a spec violation on an object that should have the attribute (xfail). Leaning toward xfail since the object exists.

### Mechanism "not operational" / "not functional" / "not yet operational" (24 calls)

These cover mechanisms where the test attempts the operation and catches an error. The mechanism may or may not be advertised. Examples:

| File | Lines | Mechanism(s) |
|------|-------|-------------|
| `test_ike.py` | 153,175,194,212,236,252,270,288,312,328,346,364,389,406,426,445 | IKE1/2 PRF and extended derive |
| `test_sp800_108_kdf.py` | 345,365,399,438,471,495,527,561,594,617,649 | SP800-108 counter/feedback/double-pipeline KDF |
| `test_double_ratchet.py` | 183,235,291,334,381,410,454,496 | X2RATCHET mechanisms |
| `test_ecdh_extended.py` | 341,390,408,440 | ECMQV derive, XEdDSA sign/verify |
| `test_kem.py` | 442 | ML-KEM CKA_PARAMETER_SET variant |
| `test_otp.py` | 273,282,291 | KIP_WRAP, KIP_MAC (specialized key types) |

**Rationale:** These tests catch exceptions from attempted operations. The module might advertise the mechanism but not fully implement it (bug) or might not support it at all (missing capability). Converting to skip would hide bugs in modules that claim to support a mechanism but get it wrong. Kept as xfail.

### v3.0 interface inconsistency (1 call)

| File | Line | Reason |
|------|------|--------|
| `test_v30_session.py` | 147 | `Module exposes v3.0 interface but C_LoginUser returns CKR_FUNCTION_NOT_SUPPORTED` |
| `test_v30_session.py` | 197 | Same |
| `test_v30_session.py` | 248 | `Module accepted CKU_CONTEXT_SPECIFIC login without an active operation` |
| `test_v30_session.py` | 257 | `Module does not support CKU_CONTEXT_SPECIFIC login (CKR_FUNCTION_NOT_SUPPORTED)` |
| `test_v30_session.py` | 307 | Same as 320/329 pattern |
| `test_v30_session.py` | 480,499,522 | C_SessionCancel returns CKR_FUNCTION_NOT_SUPPORTED despite v3.0 |
| `test_v30_session.py` | 642 | Module crashed during C_DigestInit/C_SessionCancel |
| `test_v30_session.py` | 660,676 | Non-conformant CKR for C_SessionCancel |

**Rationale:** These test that a v3.0 interface module properly implements v3.0 functions. Failing here is a spec violation (the module claims v3.0 but doesn't implement it correctly), not a missing capability. Kept as xfail.

## Files modified

- `src/pkcs11_check/testcases/test_profiles.py` (line 49)
- `src/pkcs11_check/testcases/test_trust_objects.py` (line 50)
- `src/pkcs11_check/testcases/test_validation_objects.py` (line 59)
- `src/pkcs11_check/testcases/test_mechanism_objects.py` (lines 41, 51, 71, 98)
- `src/pkcs11_check/testcases/test_hw_features.py` (lines 58, 125, 179)
- `src/pkcs11_check/testcases/test_domain_params.py` (lines 176, 186)
- `src/pkcs11_check/testcases/test_v30_session.py` (lines 286, 329, 382, 394, 418, 440, 718)
- `src/pkcs11_check/testcases/test_pqc_sign.py` (lines 155, 284)
- `src/pkcs11_check/testcases/test_kem.py` (lines 168, 376, 408)
- `src/pkcs11_check/testcases/test_hkdf_extended.py` (line 190)
