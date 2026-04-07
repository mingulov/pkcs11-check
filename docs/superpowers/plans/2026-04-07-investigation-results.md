# Investigation Results: Cross-Provider Test Failures

**Date:** 2026-04-07
**Artifacts analyzed:** kryoptic-main, nss-main, opencryptoki-master, softhsm2-main, tpm2

---

## Fixes Applied

| # | File | Issue | Impact | Status |
|---|------|-------|--------|--------|
| F1 | `acvp/aes/test_xts.py` | Tweak field missing hex-to-bytes lambda | 1,200F on OpenCryptoki | Fixed |
| F2 | `mechanism_helpers.py` | `gen_symmetric_key()` ignores `param_required` for PBE mechanisms | 18F (NSS+OCK) | Fixed |
| F3 | `test_mech_encrypt.py` | Missing `retry_on_buffer_too_small` for AEAD mechanisms | 2F (NSS) | Fixed |
| F4 | `test_mech_wrap.py` | AES_XTS/CTS missing from `_IV16_WRAP_MECHS` | 3F (OCK+kryoptic) | Fixed |
| F5 | `test_hash_ml_dsa.py` | Bare `except AssertionError: xfail()` instead of `xfail_if_known_ckr()` | Potential bug masking | Fixed |
| F6 | `test_wycheproof_rsa_oaep.py` | `_mgf_sha` key name typo in error message | Cosmetic | Fixed |
| F7 | `acvp/aes/test_cts.py` | CTS variant detection misclassifies NSS as CS3 | 399F (NSS) | Fixed |

**Estimated total false failures eliminated:** ~1,622 across all providers

---

## Cross-Provider Failures: Classification

### Correct Findings (leave as-is)

| File | Providers | Failures | Reason |
|------|-----------|----------|--------|
| `acvp/test_acvp_ecdh.py` | 4/4 | 100 each | Different CKR per module for P-384/P-521 with CKA_VALUE_LEN. Test is spec-compliant (PKCS#11 v2.40 Table 33). |
| `test_mech_sign.py` | 3/4 | 6-66 | Each provider fails on different mechanisms (kryoptic RSA/EC, NSS HMAC_GENERAL, OCK legacy MAC). |
| `test_mech_multipart.py` | 4/4 | 7-31 | Different multipart buffering bugs per module. SoftHSM2 passes AES-CBC-PAD correctly, proving test is valid. |
| `test_mech_attribute.py` | 3/4 | 4-47 | NSS CKA_LOCAL=False is a spec violation. PBE param issue now fixed (F2). |
| `test_mech_keygen.py` | 3/4 | 2-34 | NSS CKA_LOCAL=False (14), EC_MONTGOMERY bugs. PBE param issue now fixed (F2). |
| `wycheproof/test_wycheproof_aes.py` | 3/4 | 77-123 | Three different AES modes fail on three providers (kryoptic CCM, NSS KWP, OCK XTS). SoftHSM2 passes all. |
| `acvp/test_acvp_eddsa.py` | 4/4 | 4-15 | NSS non-standard EdDSA params, kryoptic accepts invalid keys. Documented deviations. |
| `security/test_arithmetic_overflow.py` | 3/4 | 3-8 | Real SIGSEGV/SIGABRT/SIGBUS crashes on overflow inputs. These ARE the findings. |

### Module-Specific: Correct Findings

| File | Provider(s) | Failures | Reason |
|------|-------------|----------|--------|
| `wycheproof/test_wycheproof_rsa_pss.py` | OCK+SoftHSM2 | 435+435 | Cross-hash PSS (SHA-256 sign + MGF1-SHA-1) is spec-valid. Both modules reject it. |
| `wycheproof/test_wycheproof_rsa_oaep.py` | SoftHSM2 | 668 | SoftHSM2 rejects non-empty OAEP labels. Test is correct per PKCS#11. |
| `wycheproof/test_wycheproof_ecdsa.py` | Kryoptic | 467 | CKR_DEVICE_ERROR on ECDSA operations. Module bug. |
| `acvp/test_acvp_mldsa.py` | Kryoptic+SoftHSM2 | 249+93 | PQC implementation incomplete. |
| `wycheproof/test_wycheproof_dsa.py` | NSS | 296 | CKR_ARGUMENTS_BAD on DSA verification. |
| `x509/test_limbo_import.py` | OpenCryptoki | 233 | CKR_USER_NOT_LOGGED_IN on cert import. |
| `acvp/aes/test_cts.py` | Kryoptic | 405 | CKR_DEVICE_ERROR on non-block-aligned CTS inputs. Module advertises CTS but crashes. |

### xfails Audit

| File | xfails | Status |
|------|--------|--------|
| `acvp/test_acvp_ecdsa.py` | 30 (RFC 6979 non-deterministic signatures) | Well-justified, no changes needed |
| `test_ike.py` | 16 (all via `xfail_if_known_ckr()`) | Model pattern, no changes needed |
| `test_hash_ml_dsa.py` | 4 bare + 1 scoped | **Fixed:** 4 bare xfails now use `xfail_if_known_ckr()` |

---

## Timeout Recovery (Part 1)

Implemented progressive retry with deselect in `file_runner.py`:
- File-level timeout no longer escalates all tests to per-test isolation
- Instead: parse partial JSONL, confirm culprit, retry with completed tests deselected
- Safety cap: 3 retries before falling back to escalation of remaining tests only
- Timeout no longer promotes files to isolation policy (only crashes do)
- `_unit_timeout_seconds()` now accepts `num_tests` for scaled file timeouts
