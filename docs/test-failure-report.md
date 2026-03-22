# Test Failure Report - 2026-03-22

Generated from Docker artifact `results.json` files across 13 providers.

## Provider Summary Table

| Provider | Passed | Failed | Skipped | XFailed | Error | Crashed | Total |
|---|---|---|---|---|---|---|---|
| bouncyhsm | 51,295 | 218 | 8,026 | 13,087 | 7 | 7 | 72,633 |
| kryoptic | 37,142 | 64 | 34,773 | 654 | 0 | 0 | 72,633 |
| kryoptic-fips | 35,275 | 77 | 34,992 | 2,274 | 15 | 15 | 72,633 |
| kryoptic-main | 37,141 | 66 | 34,773 | 653 | 0 | 0 | 72,633 |
| nss | 36,431 | 472 | 35,352 | 376 | 2 | 2 | 72,633 |
| nss-main | 35,908 | 482 | 35,866 | 375 | 2 | 2 | 72,633 |
| nss-pqc | 36,431 | 472 | 35,352 | 376 | 2 | 2 | 72,633 |
| opencryptoki | 50,407 | 77 | 21,662 | 486 | 1 | 1 | 72,633 |
| pkcs11-mock | 41 | 89 | 39 | 0 | 5 | 0 | 174 |
| qryptotoken | 1,164 | 592 | 70,647 | 9 | 221 | 218 | 72,633 |
| softhsm2 | 56,855 | 37 | 14,572 | 1,169 | 0 | 0 | 72,633 |
| softhsm2-main | 52,157 | 37 | 14,572 | 1,152 | 4,715 | 4,715 | 72,633 |
| tpm2 | 6,122 | 826 | 64,530 | 1,133 | 22 | 0 | 72,633 |

**Note:** "Crashed" column is derived from per-test `outcome=crashed` counts, which represent
tests where the PKCS#11 module segfaulted or aborted. The test runner (`pkcs11-check test`)
uses process isolation to survive these crashes, so they are captured as test outcomes rather
than aborting the entire run.

---

## Priority 1: Crashes (segfaults / aborts)

**Total:** 4,957 unique test IDs with at least one crash across providers.

### 1.1 Multi-Provider Crashes (2+ providers)

These are the most concerning -- crashes that reproduce across different PKCS#11 implementations
suggest either a test harness issue or a common bug triggered by a specific PKCS#11 operation.

#### test_ssl3.py::TestSSL3MasterKeyDerive::test_derive_master_secret

- **Providers (4):** nss, nss-main, nss-pqc, opencryptoki
- **Signal:** SIGSEGV (Segmentation fault)
- **Location:** `test_ssl3.py`, line 190
- **Analysis:** The SSL3 master key derivation mechanism (`CKM_SSL3_MASTER_KEY_DERIVE`) causes
  a segfault inside the PKCS#11 module when called with the test's parameters. This is a
  **module bug** -- both NSS and OpenCryptoki crash on this operation. The test itself is
  exercising a legitimate (if legacy) PKCS#11 mechanism.

```
Fatal Python error: Segmentation fault

Current thread 0x00007796d2e99b80 (most recent call first):
  File "/app/src/pkcs11_check/testcases/test_ssl3.py", line 190 in test_derive_master_secret
  File "/app/.venv/lib64/python3.12/site-packages/_pytest/python.py", line 166 in pytest_pyfunc_call
```

#### test_ssl3.py::TestSSL3MasterKeyDeriveDH::test_derive_master_secret_dh

- **Providers (3):** nss, nss-main, nss-pqc
- **Signal:** SIGSEGV (Segmentation fault)
- **Location:** `test_ssl3.py`, line ~190 (DH variant)
- **Analysis:** Same root cause as above. The DH variant of SSL3 master key derivation also
  crashes NSS. OpenCryptoki does not crash on this variant (only the non-DH one).

```
Fatal Python error: Segmentation fault

Current thread (most recent call first):
  File "/app/src/pkcs11_check/testcases/test_ssl3.py", line 190 in test_derive_master_secret_dh
```

### 1.2 SoftHSM2-main Crashes (4,715 tests)

SoftHSM2 built from `main` branch segfaults on Wycheproof ECDSA and ECDH test vectors.
This is a **SoftHSM2 regression** in their development branch.

| Test file | Crash count |
|---|---|
| `wycheproof/test_wycheproof_ecdsa.py` | 3,418 |
| `wycheproof/test_wycheproof_ecdh.py` | 1,297 |

```
Fatal Python error: Segmentation fault

Current thread 0x00007f587f618b80 (most recent call first):
  File "/app/src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py", line 133 in test_ecdh
```

**Analysis:** SoftHSM2 `main` has an EC-related regression causing segfaults on elliptic
curve operations. The stable release (softhsm2) does not crash on these tests. This should
be reported upstream.

### 1.3 Qryptotoken Crashes (218 tests)

Qryptotoken (Rust-based PQC token) aborts on multiple test files.

| Test file | Crash count |
|---|---|
| `wycheproof/test_wycheproof.py` | 209 |
| `test_aead.py` | 7 |
| `test_attribute_enforcement.py` | 1 |
| `test_interop.py` | 1 |

```
Fatal Python error: Aborted

Current thread 0x0000737b9ab59b80 (most recent call first):
  File "/app/python-pkcs11/pkcs11/types.py", line 1296 in encrypt
  File "/app/src/pkcs11_check/testcases/test_aead.py", line 32 in test_gcm_256_encrypt_crossverify
```

**Analysis:** Qryptotoken calls `abort()` (SIGABRT) when encountering unsupported operations
rather than returning a CKR error code. This is a **module bug** -- the PKCS#11 spec requires
returning CKR_MECHANISM_INVALID or similar, not aborting.

### 1.4 Kryoptic-FIPS Crashes (15 tests)

Kryoptic in FIPS mode aborts on CKM_EXTRACT_KEY_FROM_KEY and certain AES-CCM vectors.

| Test file | Crash count |
|---|---|
| `wycheproof/test_wycheproof_aes.py` (AES-CCM) | 12 |
| `test_misc_kdf.py` (ExtractKeyFromKey) | 3 |

```
Fatal Python error: Aborted

Current thread (most recent call first):
  File "/app/src/pkcs11_check/testcases/test_misc_kdf.py", line 537 in test_extract_from_offset_zero
```

**Analysis:** Kryoptic in FIPS mode calls `abort()` on CKM_EXTRACT_KEY_FROM_KEY (disallowed
in FIPS) and on certain AES-CCM parameter combinations (tc237-tc312 with 256-bit keys).
Should return CKR error codes instead of aborting.

### 1.5 BouncyHSM Crashes (7 tests)

BouncyHSM segfaults on large data operations (1MB+).

| Test | Signal |
|---|---|
| `test_blake2.py::TestBlake2bProperties::test_large_data` | SIGSEGV |
| `test_buffers.py::TestEncryptBufferSizes::test_1mb` | SIGSEGV |
| `test_buffers.py::TestDigestBufferSizes::test_large_input` | SIGSEGV |
| `test_digest.py::TestDigestProperties::test_digest_large_data` | SIGSEGV |
| `test_large_objects.py::TestLargeEncryption::test_encrypt_1mb_aes_cbc` | SIGSEGV |
| `test_multipart_streaming.py::...::test_sha256_large_data_crossverify[1048576]` | SIGSEGV |
| `test_multipart_streaming.py::...::test_sha512_1mb_crossverify` | SIGSEGV |

```
Fatal Python error: Segmentation fault

Current thread (most recent call first):
  File "/app/python-pkcs11/pkcs11/types.py", line 912 in digest
```

**Analysis:** BouncyHSM (a .NET-based HSM simulator) crashes when processing data buffers
of 1MB or larger. All crashes occur in either `digest` or `encrypt` calls. This is a
**BouncyHSM buffer handling bug**.

---

## Priority 2: Universal Failures (failing on 5+ providers)

**Total:** 63 tests failing on 5 or more providers.

### 2.1 Tests failing on ALL 12 providers (13 tests)

These are almost certainly **test bugs** (missing attributes in python-pkcs11 fork, missing
dependencies in Docker) rather than module issues.

#### x509/test_core_ops.py -- Missing `Attribute.PUBLIC_KEY_INFO` (10 tests)

**Providers (12):** all providers
**Root cause:** Test code references `Attribute.PUBLIC_KEY_INFO` which does not exist in the
python-pkcs11 fork yet.

```
AttributeError: type object 'Attribute' has no attribute 'PUBLIC_KEY_INFO'
```

Affected tests:
- `TestCertificateImport::test_import_der_certificate`
- `TestCertificateImport::test_certificate_type_is_x509`
- `TestCertificateSearch::test_search_by_label`
- `TestCertificateExtractFields::test_read_value_matches_der`
- `TestCertificateExtractFields::test_serial_number_readable`
- `TestCertificateExtractFields::test_subject_is_der_encoded`
- `TestCertificateExtractFields::test_issuer_is_der_encoded`
- `TestCertificateExtractFields::test_self_signed_subject_equals_issuer`
- `TestCertificateDestroy::test_destroy_certificate`

#### x509/test_lifecycle.py -- Missing `Attribute.PUBLIC_KEY_INFO` (3 tests)

**Providers (12):** all providers

```
AttributeError: type object 'Attribute' has no attribute 'PUBLIC_KEY_INFO'
```

Affected tests:
- `TestCertificateLifecycle::test_cert_id_assignment`
- `TestCertificateLifecycle::test_cert_modifiability`
- `TestCertificateLifecycle::test_cert_token_persistence`

#### test_interop_openssl.py::TestP11KitProxy::test_p11kit_proxy_exists

**Providers (12):** all providers

```
AssertionError: p11-kit-proxy.so not found
assert False
```

**Analysis:** p11-kit is not installed in the Docker test containers. This test should either
be skipped when p11-kit is unavailable or p11-kit should be added to the Docker images.

### 2.2 Tests failing on 11 providers (9 tests)

All are CKR raw subprocess tests that crash with `returncode=-11` (SIGSEGV).

#### ckr/test_ckr_raw_attrs.py -- Subprocess segfaults (3 tests)

**Providers (11):** all except softhsm2, softhsm2-main
**Tests:**
- `TestKeyFunctionNotPermitted::test_decrypt_not_permitted`
- `TestKeyFunctionNotPermitted::test_encrypt_not_permitted`
- `TestKeyFunctionNotPermitted::test_sign_not_permitted`

```
AssertionError: Crash:
assert -11 == 0
```

**Analysis:** These tests run raw PKCS#11 calls in a subprocess using `RawPKCS11`. The
subprocess segfaults (`rc=-11`) on almost all providers except SoftHSM2. The tests assert
`returncode == 0`, which fails because the module crashes instead of returning a CKR error.
This reveals a widespread module robustness issue but the test assertion may need adjustment
to account for crash-prone modules.

#### ckr/test_ckr_raw_buffer.py -- Subprocess segfaults (1 test)

**Providers (11):** all except softhsm2, softhsm2-main
- `TestBufferTooSmall::test_encrypt_buffer_too_small`

Same pattern: subprocess SIGSEGV when testing buffer-too-small conditions.

#### ckr/test_ckr_raw_state.py -- Subprocess segfaults (4 tests)

**Providers (11):** all except softhsm2, softhsm2-main
- `TestOperationActive::test_double_decrypt_init`
- `TestOperationActive::test_double_digest_init`
- `TestOperationActive::test_double_encrypt_init`
- `TestOperationActive::test_double_sign_init`
- `TestOperationActive::test_encrypt_then_sign_init`

Same pattern: subprocess SIGSEGV when testing operation-state violations.

#### ckr/test_ckr_universal.py::test_cryptoki_not_initialized_via_subprocess

**Providers (10):** all except softhsm2, softhsm2-main, tpm2

```
AssertionError: Crash:
assert -11 == 0
 +  where -11 = CompletedProcess(..., returncode=-11, ...).returncode
```

### 2.3 Tests failing on 10 providers (13 tests)

#### ckr/test_ckr_raw_buffer.py (2 tests)

**Providers (10):** all except softhsm2, softhsm2-main, tpm2
- `TestBufferTooSmall::test_digest_buffer_too_small`
- `TestBufferTooSmall::test_sign_buffer_too_small`

Same subprocess SIGSEGV pattern.

#### ckr/test_ckr_raw_multipart.py (10 tests)

**Providers (10):** all except softhsm2, softhsm2-main, tpm2
- `TestMultipartNotInitialized::test_decrypt_final_no_init`
- `TestMultipartNotInitialized::test_decrypt_update_no_init`
- `TestMultipartNotInitialized::test_digest_final_no_init`
- `TestMultipartNotInitialized::test_digest_update_no_init`
- `TestMultipartNotInitialized::test_encrypt_final_no_init`
- `TestMultipartNotInitialized::test_encrypt_update_no_init`
- `TestMultipartNotInitialized::test_sign_final_no_init`
- `TestMultipartNotInitialized::test_sign_update_no_init`
- `TestMultipartNotInitialized::test_verify_final_no_init`
- `TestMultipartNotInitialized::test_verify_update_no_init`

```
AssertionError: Crash or error:
assert -11 == 0
```

### 2.4 Tests failing on 9 providers (5 tests)

#### x509/test_core_ops.py -- Missing v3.0 certificate attributes

**Providers (9):** all except softhsm2, softhsm2-main, tpm2
- `TestV30CertAttributes::test_v30_cert_attr_accepted[AKID]` -- `Attribute.AKID` missing
- `TestV30CertAttributes::test_v30_cert_attr_accepted[HASH_OF_ISSUER_PUBLIC_KEY]` -- `Attribute.PUBLIC_KEY_INFO` missing
- `TestV30CertAttributes::test_v30_cert_attr_accepted[HASH_OF_SUBJECT_PUBLIC_KEY]` -- `Attribute.PUBLIC_KEY_INFO` missing
- `TestV30CertAttributes::test_v30_cert_attr_accepted[PUBLIC_KEY_INFO]` -- `Attribute.PUBLIC_KEY_INFO` missing
- `TestV30CertAttributes::test_v30_cert_attr_accepted[SKID]` -- `Attribute.SKID` missing

```
AttributeError: type object 'Attribute' has no attribute 'PUBLIC_KEY_INFO'
AttributeError: type object 'Attribute' has no attribute 'AKID'
AttributeError: type object 'Attribute' has no attribute 'SKID'
```

**Analysis:** Test bug -- these v3.0 certificate attributes (`PUBLIC_KEY_INFO`, `AKID`, `SKID`)
have not been added to the python-pkcs11 fork's `Attribute` enum yet.

### 2.5 Tests failing on 7 providers (1 test)

#### test_object_visibility.py::TestCrossSessionModification::test_modify_value_cross_session

**Providers (7):** nss, nss-main, nss-pqc, opencryptoki, softhsm2, softhsm2-main, tpm2

```
pkcs11.exceptions.AttributeValueInvalid
```

**Analysis:** Modifying an object's VALUE attribute from a different session is rejected by
7 providers. This may be correct module behavior (many modules restrict cross-session
attribute modification). Likely a **test expectation issue**.

### 2.6 Tests failing on 6 providers (15 tests)

#### ckr/test_ckr_encrypt.py::test_key_size_range

**Providers (6):** nss, nss-main, nss-pqc, opencryptoki, softhsm2, softhsm2-main

```
AttributeError: type object 'KeyType' has no attribute 'DES'. Did you mean: 'AES'?
```

**Analysis:** Test bug -- `KeyType.DES` is not defined in the python-pkcs11 fork.

#### test_aes_modes.py::TestAESMACGeneral (2 tests)

**Providers (6):** kryoptic, kryoptic-main, nss, nss-main, nss-pqc, opencryptoki
- `test_aes_mac_general_sign_verify`
- `test_aes_mac_general_different_keys`

```
pkcs11.exceptions.ArgumentsBad: Unexpected argument to mechanism_param
```

**Analysis:** The mechanism parameter encoding for AES-MAC-GENERAL is not handled correctly
by the python-pkcs11 fork. Likely a **binding bug**.

#### test_tls12.py (7 tests)

**Providers (6):** kryoptic, kryoptic-fips, kryoptic-main, nss, nss-main, nss-pqc
- `TestTLS12MasterKeyDerive::test_master_key_derive`
- `TestTLS12MasterKeyDerive::test_master_key_derive_dh`
- `TestTLS12Extended::test_extended_master_key_derive`
- `TestTLS12Extended::test_extended_master_key_derive_dh`
- `TestTLS12Extended::test_different_session_hashes_produce_different_secrets`
- `TestTLS12KeyAndMacDerive::test_key_and_mac_derive`
- `TestTLS12Mac::test_tls_mac`

```
pkcs11.exceptions.ArgumentsBad: Unexpected argument to mechanism_param
```

**Analysis:** TLS 1.2 mechanism parameter structures (`CK_TLS12_MASTER_KEY_DERIVE_PARAMS`,
`CK_TLS12_KEY_MAT_PARAMS`) are not implemented in the python-pkcs11 fork. This is a
**binding limitation**.

#### test_hkdf_extended.py::TestHKDFKeyGen::test_hkdf_key_gen_usable_for_derive

**Providers (6):** kryoptic, kryoptic-fips, kryoptic-main, nss, nss-main, nss-pqc

```
pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
```

**Analysis:** Test needs to pass explicit capabilities when generating an HKDF key. **Test bug**.

#### test_key_flags.py::test_extractable_and_never_extractable_consistent

**Providers (6):** nss, nss-main, nss-pqc, opencryptoki, qryptotoken, tpm2

```
assert True is False
```

**Analysis:** These providers report `CKA_EXTRACTABLE=True` and `CKA_NEVER_EXTRACTABLE=True`
simultaneously, which the spec says should be mutually exclusive. **Module quirk** -- several
modules do not properly track the NEVER_EXTRACTABLE flag.

#### test_sensitivity.py::test_non_extractable_by_default

**Providers (6):** nss, nss-main, nss-pqc, opencryptoki, qryptotoken, tpm2

```
assert True is False
```

**Analysis:** These providers default to `CKA_EXTRACTABLE=True` for generated keys. The
PKCS#11 spec does not mandate a specific default, so this is a **test expectation issue**.

#### test_ro_session_restrictions.py (2 tests)

**Providers (6):** bouncyhsm, nss, nss-main, nss-pqc, opencryptoki, tpm2
- `test_unwrap_to_session_object_in_ro_succeeds`
- `test_unwrap_to_token_object_in_ro_fails`

```
pkcs11.exceptions.MechanismInvalid
```

**Analysis:** Key unwrap mechanism not supported on these providers. Test should check
mechanism availability first. **Test bug**.

#### test_tookan.py::test_extractable_cannot_escalate_on_copy

**Providers (5):** bouncyhsm, nss, nss-main, nss-pqc, tpm2

```
AssertionError: EXTRACTABLE escalated on copy -- Tookan vulnerability
assert True is False
```

**Analysis:** These 5 providers allow escalating `CKA_EXTRACTABLE` from False to True
during a `C_CopyObject` call. This is a known Tookan vulnerability. **Module security issue**.

### 2.7 Tests failing on 5 providers (7 tests)

#### test_attribute_fuzz.py::test_negative_key_length

**Providers (5):** bouncyhsm, nss, nss-main, nss-pqc, tpm2

```
pkcs11.exceptions.TemplateInconsistent
```

**Analysis:** Providers reject negative key length with different error codes than expected.
Likely a **test expectation issue**.

#### test_concurrent_sessions.py::test_use_key_from_concurrent_session

**Providers (5):** nss, nss-main, nss-pqc, qryptotoken, tpm2

```
pkcs11.exceptions.TokenWriteProtected
```

**Analysis:** Module does not allow concurrent session key sharing. **Module limitation**.

#### test_key_flags.py::test_generated_rsa_keypair_is_local

**Providers (5):** nss, nss-main, nss-pqc, qryptotoken, tpm2

```
assert False is True
```

**Analysis:** `CKA_LOCAL` flag is not set on generated RSA keypairs. Some modules do not
implement this flag. **Module limitation**.

#### test_object_size.py::test_rsa_key_larger_than_aes

**Providers (5):** nss, nss-main, nss-pqc, qryptotoken, tpm2

```
AssertionError: RSA-2048 size (0) should be > AES-256 size (0)
assert 0 > 0
```

**Analysis:** `C_GetObjectSize` returns 0 for all objects on these modules. **Module limitation**
-- `C_GetObjectSize` is optional per spec.

#### test_subprocess_safety.py::test_reload_cycle_5x

**Providers (5):** nss, nss-main, nss-pqc, qryptotoken, tpm2

```
AssertionError: Reload cycle crashed (rc=1): pkcs11.exceptions.NoSuchToken
```

**Analysis:** These modules do not handle repeated `C_Initialize`/`C_Finalize` cycles cleanly.
**Module limitation**.

#### test_v30_session.py::test_cancel_after_digest_init_subprocess

**Providers (5):** bouncyhsm, kryoptic-main, nss, nss-main, nss-pqc

```
AssertionError: Expected C_SessionCancel to return CKR_OK after DigestInit, got: 'CANCEL:0x00000051'
```

**Analysis:** `C_SessionCancel` returns `CKR_FUNCTION_NOT_SUPPORTED` (0x54) or other errors
instead of `CKR_OK`. Most modules have not implemented this v3.0 function. **Module limitation**.

---

## Priority 3: Universal XFails

**Total:** 21,744 xfail occurrences across all providers, grouped into major categories below.

### 3.1 RSA-PSS Salt Length Mismatch (2,870 occurrences, 6 providers)

| Salt Length | Count | Providers |
|---|---|---|
| sLen=32 | 1,155 | bouncyhsm, kryoptic-fips, opencryptoki, softhsm2, softhsm2-main, tpm2 |
| sLen=20 | 687 | bouncyhsm, kryoptic-fips, opencryptoki, softhsm2, softhsm2-main, tpm2 |
| sLen=0 | 350 | bouncyhsm, kryoptic-fips, opencryptoki, softhsm2, softhsm2-main, tpm2 |
| sLen=48 | 226 | bouncyhsm, kryoptic-fips, opencryptoki, softhsm2, softhsm2-main, tpm2 |
| sLen=64 | 226 | bouncyhsm, kryoptic-fips, opencryptoki, softhsm2, softhsm2-main, tpm2 |
| sLen=28 | 226 | bouncyhsm, kryoptic-fips, opencryptoki, softhsm2, softhsm2-main, tpm2 |

**Reason:** Wycheproof RSA-PSS test vectors use explicit salt lengths that differ from the
hash output length. PKCS#11 `CK_RSA_PKCS_PSS_PARAMS` requires specifying `sLen`, but most
modules only accept `sLen == hash_length` and reject other valid-per-RFC values.

### 3.2 PBES2 Key Derivation (1,080 occurrences, 1 provider)

- **Provider:** kryoptic-fips only
- **Reason:** FIPS mode disables PBES2 password-based key derivation (all HMAC-SHA variants).
- **Tests:** `wycheproof/test_wycheproof_pbes2.py`

### 3.3 HMAC Operation Failures (426 occurrences, 4 providers)

| Error | Count | Providers |
|---|---|---|
| GeneralError | 246 | bouncyhsm, tpm2 |
| KeyHandleInvalid | 132 | bouncyhsm |
| KeySizeRange | 48 | softhsm2, softhsm2-main |

**Reason:** Various HMAC key import/operation issues with Wycheproof test vectors. Some
modules reject HMAC keys below certain size thresholds.

### 3.4 HMAC Key Size Restrictions (78 occurrences, 3 providers)

| Reason | Count | Providers |
|---|---|---|
| Key too short for hash | 12 | softhsm2, softhsm2-main |
| Cannot import 32-byte HMAC key | 66 | tpm2 |

### 3.5 Kryoptic CKR_DEVICE_ERROR on ML-DSA Verify (45 occurrences, 3 providers)

- **Providers:** kryoptic, kryoptic-fips, kryoptic-main
- **Reason:** Kryoptic returns `CKR_DEVICE_ERROR` instead of `CKR_SIGNATURE_INVALID` for
  tampered ML-DSA signatures. The test xfails because verification failure semantics differ.

### 3.6 C_LoginUser Not Implemented (30 occurrences, 6 providers)

- **Providers:** bouncyhsm, kryoptic, kryoptic-fips, kryoptic-main, opencryptoki, qryptotoken
- **Tests:** `test_v30_session.py` (C_LoginUser and context-specific login tests)

### 3.7 AES-GCM Parameter Combinations (26 occurrences, 7 providers)

- **Providers:** kryoptic, kryoptic-fips, kryoptic-main, opencryptoki, softhsm2, softhsm2-main, tpm2
- **Reason:** Non-standard IV lengths or tag sizes rejected by modules.

### 3.8 SP800-108 Feedback KDF (18 occurrences, 6 providers)

- **Providers:** kryoptic, kryoptic-fips, kryoptic-main, nss, nss-main, nss-pqc
- **Reason:** `CKM_SP800_108_FEEDBACK_KDF` mechanism listed as supported but derivation fails.

### 3.9 RSA-AES Key Wrap (15 occurrences, 5 providers)

- **Providers:** bouncyhsm, kryoptic, kryoptic-fips, kryoptic-main, opencryptoki
- **Reason:** `CKM_RSA_AES_KEY_WRAP` mechanism not functional despite being advertised.

### 3.10 SSL3 MAC Mechanisms (24 occurrences, 4 providers)

- **Providers:** nss, nss-main, nss-pqc, opencryptoki
- **Reason:** `CKM_SSL3_MD5_MAC` and `CKM_SSL3_SHA1_MAC` mechanism parameter encoding not
  supported by the python-pkcs11 fork (`Unexpected argument to mechanism_param`).

### 3.11 IKE/IKEv2 Derivation Mechanisms (36 occurrences, 3 providers)

- **Providers:** nss, nss-main, nss-pqc
- **Mechanisms:** `CKM_IKE_PRF_DERIVE`, `CKM_IKE1_PRF_DERIVE`, `CKM_IKE1_EXTENDED_DERIVE`,
  `CKM_IKE2_PRF_PLUS_DERIVE`
- **Reason:** Mechanism parameter structures not implemented in python-pkcs11 fork.

### 3.12 AES-CMAC-GENERAL (7 occurrences, 7 providers)

- **Providers:** bouncyhsm, kryoptic, kryoptic-fips, kryoptic-main, nss, nss-main, nss-pqc
- **Reason:** AES-CMAC-GENERAL sign operation fails across most providers.

### 3.13 HKDF Data Derive (9 occurrences, 3 providers)

- **Providers:** kryoptic, kryoptic-fips, kryoptic-main
- **Reason:** `CKM_HKDF_DATA` derive mechanism not operational.

### 3.14 Security: CKA_COPYABLE Escalation (4 occurrences, 4 providers)

- **Providers:** bouncyhsm, nss, nss-main, nss-pqc
- **Reason:** `CKA_COPYABLE` can be escalated from `False` to `True`, violating the
  one-way rule. This is a **security concern** tracked as an xfail.

---

## Priority 4: Errors (outcome=error)

**Total:** 4 unique test IDs with `outcome=error`.

Errors differ from failures in that they occur during test setup/teardown (fixture errors)
rather than during the test body itself.

### test_benchmark.py::test_bench_rsa2048_sign

**Providers (2):** qryptotoken, tpm2

| Provider | Error |
|---|---|
| qryptotoken | `pkcs11.exceptions.MechanismInvalid` |
| tpm2 | `pkcs11.exceptions.AttributeValueInvalid` |

**Analysis:** RSA key generation fails during fixture setup. Qryptotoken does not support RSA,
and tpm2 rejects the key template attributes.

### ckr/test_ckr_codes.py::TestCKRMechanismErrors::test_ckr_mechanism_invalid

**Providers (1):** pkcs11-mock

```
pkcs11.exceptions.SessionCount
```

**Analysis:** pkcs11-mock hits session limit during test setup. **Environment limitation**.

### test_attribute_defaults.py::TestSecretKeyDefaults::test_token_is_false

**Providers (1):** tpm2

```
pkcs11.exceptions.FunctionNotSupported
```

**Analysis:** tpm2-pkcs11 does not support AES key generation for this template.

### test_attribute_defaults.py::TestKeyPairDefaults::test_public_key_local

**Providers (1):** tpm2

```
pkcs11.exceptions.AttributeValueInvalid
```

**Analysis:** tpm2-pkcs11 rejects the RSA key generation template during fixture setup.

---

## Summary of Root Causes

| Category | Count | Root Cause |
|---|---|---|
| Missing python-pkcs11 attributes/enums | 19 tests (12+ provs) | `PUBLIC_KEY_INFO`, `AKID`, `SKID`, `DES` not in fork |
| Missing mechanism param structs | 20+ tests (6 provs) | TLS12, SSL3, IKE params not implemented |
| CKR subprocess segfaults | 22 tests (10-11 provs) | Raw PKCS#11 calls crash most modules |
| SoftHSM2-main EC regression | 4,715 tests (1 prov) | ECDSA/ECDH segfaults in dev branch |
| Qryptotoken abort() | 218 tests (1 prov) | Module calls abort instead of returning CKR |
| Kryoptic-FIPS abort() | 15 tests (1 prov) | FIPS mode aborts on disallowed operations |
| BouncyHSM large buffer crash | 7 tests (1 prov) | Buffer overflow at 1MB+ |
| SSL3 derive segfault | 2 tests (3-4 provs) | NSS/OpenCryptoki crash on SSL3 derivation |
| RSA-PSS sLen mismatch | 2,870 xfails (6 provs) | Modules only accept sLen==hashLen |
| Missing Docker dependency | 1 test (12 provs) | p11-kit not installed |

### Recommended Actions

1. **Add missing attributes** to python-pkcs11 fork: `PUBLIC_KEY_INFO`, `AKID`, `SKID`, `KeyType.DES`
2. **Implement TLS12/SSL3/IKE mechanism parameter structs** in python-pkcs11 fork
3. **File SoftHSM2 upstream bug** for ECDSA/ECDH segfaults on main branch
4. **File Qryptotoken upstream bug** for abort() instead of CKR error codes
5. **File Kryoptic bug** for abort() in FIPS mode (should return CKR_MECHANISM_INVALID)
6. **File BouncyHSM bug** for large buffer segfaults
7. **Adjust CKR subprocess tests** to handle expected crashes (xfail or catch rc=-11)
8. **Install p11-kit** in Docker images or skip test_p11kit_proxy_exists when unavailable

## Gap Analysis

### 1. Test Count Anomaly
- **pkcs11-mock**: only 174 tests (vs 72,633 standard) - this is expected, pkcs11-mock is a minimal stub

### 2. SoftHSM2-main Regression (CRITICAL)
- 4,715 errors (crashes) - EC regression in dev branch
- Passes dropped from 56,855 (stable) to 52,157 (main)
- Affects ALL Wycheproof ECDSA (3,418 vectors) and ECDH (1,297 vectors)
- **Action**: Document as known SoftHSM2 dev branch issue, not a pkcs11-check bug

### 3. SoftHSM2-main report.jsonl Bloat
- `report.jsonl` is 4.7GB (36M lines) vs ~170MB for other providers
- The 4,715 crashed EC tests generate massive JSONL from iterative deselect retries
- **Action**: Consider limiting report.jsonl size or compressing

### 4. High Skip Counts
- **Kryoptic**: 48% skipped - mostly unsupported curves (secp256k1, brainpool, secp224r1)
- **NSS**: 49% skipped - same curve limitations
- **OpenCryptoki**: 30% skipped - no Montgomery curves, no PBKDF2
- **TPM2**: 89% skipped - very limited mechanism support
- These are genuine module limitations, not test bugs

### 5. Top Skip Reasons Across All Providers
| Reason | Count | Providers |
|--------|-------|-----------|
| Cannot import EC private key for ECDH | ~8,000 per provider | kryoptic, nss, opencryptoki |
| Cannot import EC key for secp256k1 | ~4,600 per provider | kryoptic, nss, tpm2 |
| Cannot import EC key for secp224r1 | ~4,500 per provider | kryoptic, nss, tpm2 |
| Cannot decode ASN ECDH vector | ~2,100 per provider | bouncyhsm, opencryptoki, softhsm2 |
| PKCS5_PBKD2 not supported | ~1,500 per provider | bouncyhsm, opencryptoki, softhsm2 |
| DSA_SHA256 not supported | ~1,500 per provider | bouncyhsm, qryptotoken, tpm2 |
| Cannot import Montgomery private key | ~4,000 per provider | opencryptoki, softhsm2 |

### 6. BouncyHSM XFail Anomaly
- 13,087 xfails - unusually high (18% of tests)
- Likely caused by BouncyHSM accepting invalid vectors that other modules reject
- **Action**: Investigate if xfail logic is too aggressive for this module

### 7. Kryoptic-FIPS Extra XFails
- 2,274 xfails vs 654 for standard Kryoptic
- Difference (~1,620) is from FIPS restrictions disabling non-FIPS algorithms
- Expected behavior - FIPS mode correctly rejects non-approved operations

### 8. Qryptotoken Viability
- Only 1.6% pass rate (1,164/72,633)
- 218 crashes, 592 failures, 221 errors
- 97% of tests skipped - module supports very few mechanisms
- **Action**: Consider marking as experimental or reducing test scope

### 9. NSS-main vs NSS Stable
- nss-main: 523 fewer passes, 514 more skips than nss stable
- Some mechanisms may have been removed or renamed in NSS tip
- nss-pqc identical to nss stable (same Fedora Rawhide package)

### 10. Potential Test Bugs (tests failing everywhere)
- **x509/test_core_ops.py**: ALL tests fail on ALL 12 providers - cert import broken in test
- **CKR raw subprocess tests**: 22 tests fail on 10-11 providers - subprocess crash (rc=-11)
- **test_interop_openssl.py::test_p11kit_proxy_exists**: fails on all 12 - p11-kit not in Docker
- **Action**: These are test bugs, not module bugs. Fix or mark as known issues.
