# Test Failure Report - 2026-03-23

Generated from Docker artifact `results.json` files across 12 providers.
Previous report: 2026-03-22. This is a full refresh.

## Provider Summary

| Provider | Passed | Failed | Skipped | XFailed | Error | Crashed | Total |
|----------|--------|--------|---------|---------|-------|---------|-------|
| bouncyhsm | 51,336 | 180 | 8,035 | 13,088 | 7 | 7 | 72,646 |
| kryoptic | 37,187 | 27 | 34,772 | 660 | 0 | 0 | 72,646 |
| kryoptic-fips | 35,322 | 39 | 34,990 | 2,280 | 15 | 15 | 72,646 |
| kryoptic-main | 37,190 | 25 | 34,771 | 660 | 0 | 0 | 72,646 |
| nss | 36,477 | 440 | 35,354 | 373 | 2 | 2 | 72,646 |
| nss-main | 35,953 | 450 | 35,868 | 373 | 2 | 2 | 72,646 |
| nss-pqc | 36,478 | 440 | 35,354 | 372 | 2 | 2 | 72,646 |
| opencryptoki | 50,460 | 25 | 21,670 | 490 | 1 | 1 | 72,646 |
| pkcs11-mock | 61 | 77 | 31 | 0 | 5 | 0 | 174 |
| softhsm2 | 56,872 | 19 | 14,585 | 1,170 | 0 | 0 | 72,646 |
| softhsm2-main | 52,173 | 20 | 14,585 | 1,153 | 4,715 | 4,715 | 72,646 |
| tpm2 | 6,136 | 815 | 64,541 | 1,132 | 22 | 0 | 72,646 |

**Notes:**
- "Crashed" tests are a subset of the "Error" column. They represent tests where the module segfaulted (SIGSEGV) or aborted (SIGABRT).
- The test runner uses process isolation to survive crashes, capturing them as test outcomes.
- qryptotoken is not included in this run (build issues).
- pkcs11-mock is a v3.1 stub; most failures are expected due to limited mechanism support.

---

## Priority 1: Crashes

**Total crash events:** 4,744 across 7 providers.

### softhsm2-main: 4,715 crashes

All crashes are in Wycheproof ECDH and ECDSA vectors involving brainpool and sect (binary) curves.
SoftHSM2 main branch segfaults when processing these curve parameters.

| Test File | Curve | Crashes |
|-----------|-------|---------|
| test_wycheproof_ecdh.py | brainpoolP224r1 | 635 |
| test_wycheproof_ecdh.py | sect283k1 | 115 |
| test_wycheproof_ecdh.py | sect571k1 | 115 |
| test_wycheproof_ecdh.py | sect409k1 | 113 |
| test_wycheproof_ecdh.py | sect283r1 | 108 |
| test_wycheproof_ecdh.py | sect409r1 | 106 |
| test_wycheproof_ecdh.py | sect571r1 | 105 |
| | **ECDH subtotal** | **1297** |
| test_wycheproof_ecdsa.py | brainpoolP224r1 | 238 |
| test_wycheproof_ecdsa.py | secp160r1 | 221 |
| test_wycheproof_ecdsa.py | secp160r2 | 220 |
| test_wycheproof_ecdsa.py | secp192r1 | 220 |
| test_wycheproof_ecdsa.py | brainpoolP224r1 | 219 |
| test_wycheproof_ecdsa.py | secp224k1 | 219 |
| test_wycheproof_ecdsa.py | secp192k1 | 218 |
| test_wycheproof_ecdsa.py | secp192r1 | 218 |
| test_wycheproof_ecdsa.py | secp160k1 | 217 |
| test_wycheproof_ecdsa.py | secp192k1 | 217 |
| test_wycheproof_ecdsa.py | brainpoolP224r1 | 216 |
| test_wycheproof_ecdsa.py | secp224k1 | 190 |
| test_wycheproof_ecdsa.py | secp160r1 | 169 |
| test_wycheproof_ecdsa.py | secp160k1 | 167 |
| test_wycheproof_ecdsa.py | secp160r2 | 167 |
| test_wycheproof_ecdsa.py | secp224k1 | 165 |
| test_wycheproof_ecdsa.py | secp224k1 | 137 |
| | **ECDSA subtotal** | **3418** |

```
Fatal Python error: Segmentation fault
File "/app/src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py", line 133 in test_ecdh
File "/app/python-pkcs11/pkcs11/types.py", line 1472 in verify  (ECDSA)
```

**Classification:** Module bug -- SoftHSM2 main branch crashes on brainpoolP224r1 and binary (sect) curve operations.
The stable release (softhsm2) does not crash on these vectors.

### bouncyhsm: 7 crashes

All crashes are segfaults in large data operations (1MB+ encrypt/digest).

| Test | Location |
|------|----------|
| `TestBlake2bProperties::test_large_data` | types.py encrypt/digest |
| `TestEncryptBufferSizes::test_1mb` | types.py encrypt/digest |
| `TestDigestBufferSizes::test_large_input` | types.py encrypt/digest |
| `TestDigestProperties::test_digest_large_data` | types.py encrypt/digest |
| `TestLargeEncryption::test_encrypt_1mb_aes_cbc` | types.py encrypt/digest |
| `TestMultipartDigest::test_sha256_large_data_crossverify[1048576]` | types.py encrypt/digest |
| `TestMultipartDigest::test_sha512_1mb_crossverify` | types.py encrypt/digest |

```
Fatal Python error: Segmentation fault

Current thread 0x0000703585735300 (most recent call first):
  File "/app/python-pkcs11/pkcs11/types.py", line 912 in digest
  File "/app/src/pkcs11_check/testcases/test_blake2.py", line 137 in test_large_data
  File "/app/.venv/lib/python3.12/site-packages/_pytest/python.py", line 166 in pytest_pyfunc_call
  File "/app/.venv/lib/python3.12/site-packages/pluggy/_callers.py", line 121 in _multicall
  File "/app/.venv/lib/python3.12/site-packages/pluggy/_mana
```

**Classification:** Module bug -- BouncyHSM segfaults on large (1MB) buffer operations.

### kryoptic-fips: 15 crashes

Crashes in two areas: CKM_EXTRACT_KEY_FROM_KEY (3 crashes) and AES-CCM Wycheproof vectors (12 crashes).

**CKM_EXTRACT_KEY_FROM_KEY (SIGABRT):**

- `TestExtractKeyFromKey::test_extract_from_offset_zero`
- `TestExtractKeyFromKey::test_extract_at_byte_boundary_offset`
- `TestExtractKeyFromKey::test_extract_different_offsets_yield_different_keys`

```
Fatal Python error: Aborted

Current thread 0x0000775410181b80 (most recent call first):
  File "/app/src/pkcs11_check/testcases/test_misc_kdf.py", line 537 in test_extract_from_offset_zero
  File "/app/.venv/lib64/python3.12/site-packages/_pytest/python.py", line 166 in pytest_pyfunc_call
  File "/app/.venv/lib64/python3.12/site-packages/pluggy/_callers.py", line 121 in _multicall
  File "/app/.v
```

**AES-CCM Wycheproof vectors (SIGABRT):**

12 test vectors abort: tc237-valid, tc238-valid, tc239-valid, tc240-valid, tc273-valid, tc274-valid, ...

```
Fatal Python error: Aborted

Current thread 0x00007429a5e61b80 (most recent call first):
  File "/app/python-pkcs11/pkcs11/types.py", line 1296 in encrypt
  File "/app/src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py", line 284 in test_aes_ccm
  File "/app/.venv/lib64/python3.12/site-packages/_pytest/python.py", line 166 in pytest_pyfunc_call
  File "/app/.venv/lib64/python3.12/site-pa
```

**Classification:** Module bug -- Kryoptic FIPS build aborts on CKM_EXTRACT_KEY_FROM_KEY and certain AES-CCM parameters.

### NSS (all variants) + OpenCryptoki: SSL3 master key derive crashes

| Test | Providers |
|------|-----------|
| `TestSSL3MasterKeyDerive::test_derive_master_secret` | nss, nss-main, nss-pqc, opencryptoki |
| `TestSSL3MasterKeyDeriveDH::test_derive_master_secret_dh` | nss, nss-main, nss-pqc |

```
Fatal Python error: Segmentation fault

Current thread 0x00007eb590e4bb80 (most recent call first):
  File "/app/src/pkcs11_check/testcases/test_ssl3.py", line 190 in test_derive_master_secret
  File "/app/.venv/lib64/python3.12/site-packages/_pytest/python.py", line 166 in pytest_pyfunc_call
  File "/app/.venv/lib64/python3.12/site-packages/pluggy/_callers.py", line 121 in _multicall
  File "/app/.venv/lib64/python3.12/site-packages/pluggy/_manager.py", line 120 in _hookexec
  File "/app/.venv/
```

**Classification:** Module bug -- CKM_SSL3_MASTER_KEY_DERIVE causes SIGSEGV in NSS and OpenCryptoki.
These are legacy SSL3 mechanisms; the crash is a module-side NULL pointer dereference.

---

## Priority 2: Tests Failing on 5+ Providers

**15 tests** fail across 5 or more providers (excluding pkcs11-mock).

### test_ckr_encrypt.py

#### `TestEncryptDataErrors::test_key_size_range`

**Providers (6):** nss, nss-main, nss-pqc, opencryptoki, softhsm2, softhsm2-main

```
AttributeError: type object 'KeyType' has no attribute 'DES'. Did you mean: 'AES'?
```

**Classification:** pkcs11-check bug -- python-pkcs11 fork missing `KeyType.DES` enum.

### test_ckr_raw_buffer.py

#### `TestBufferTooSmall::test_digest_buffer_too_small`

**Providers (5):** bouncyhsm, kryoptic, nss, nss-main, nss-pqc

```
AssertionError: Crash: Traceback (most recent call last):
    File "<string>", line 31, in <module>
  AssertionError: Expected BUFFER_TOO_SMALL, got 0x00000000
assert 1 == 0
```

**Classification:** Module limitation -- C_Digest returns CKR_OK instead of CKR_BUFFER_TOO_SMALL when output buffer is too small.

### test_attribute_fuzz.py

#### `TestMalformedAttributes::test_negative_key_length`

**Providers (5):** bouncyhsm, nss, nss-main, nss-pqc, tpm2

```
pkcs11.exceptions.TemplateInconsistent
```

**Classification:** Module limitation -- some modules reject negative key lengths differently.

### test_key_flags.py

#### `TestNeverExtractable::test_extractable_and_never_extractable_consistent`

**Providers (5):** nss, nss-main, nss-pqc, opencryptoki, tpm2

```
pkcs11.exceptions.FunctionNotSupported
```

**Classification:** Module limitation -- modules fail to enforce CKA_NEVER_EXTRACTABLE / CKA_EXTRACTABLE consistency.

### test_tls12.py

#### `TestTLS12Extended::test_different_session_hashes_produce_different_secrets`

**Providers (6):** kryoptic, kryoptic-fips, kryoptic-main, nss, nss-main, nss-pqc

```
ValueError: need more than 2 values to unpack
```

**Classification:** pkcs11-check bug -- TLS derive returns fewer values than test expects.

#### `TestTLS12Extended::test_extended_master_key_derive`

**Providers (6):** kryoptic, kryoptic-fips, kryoptic-main, nss, nss-main, nss-pqc

```
ValueError: need more than 2 values to unpack
```

**Classification:** pkcs11-check bug -- TLS derive returns fewer values than test expects.

#### `TestTLS12Extended::test_extended_master_key_derive_dh`

**Providers (6):** kryoptic, kryoptic-fips, kryoptic-main, nss, nss-main, nss-pqc

```
ValueError: need more than 2 values to unpack
```

**Classification:** pkcs11-check bug -- TLS derive returns fewer values than test expects.

#### `TestTLS12Mac::test_tls_mac`

**Providers (6):** kryoptic, kryoptic-fips, kryoptic-main, nss, nss-main, nss-pqc

```
TypeError: keywords must be strings
```

**Classification:** pkcs11-check bug -- mechanism parameter construction error in test code.

#### `TestTLSNegativeAttributes::test_derive_without_derive_attr[TLS12_EXTENDED_MASTER_KEY_DERIVE]`

**Providers (6):** kryoptic, kryoptic-fips, kryoptic-main, nss, nss-main, nss-pqc

```
AttributeError: 'SecretKey' object has no attribute 'derive_key'
```

**Classification:** pkcs11-check bug -- `SecretKey` missing `derive_key` method in python-pkcs11 fork.

#### `TestTLSNegativeAttributes::test_derive_without_derive_attr[TLS12_EXTENDED_MASTER_KEY_DERIVE_DH]`

**Providers (6):** kryoptic, kryoptic-fips, kryoptic-main, nss, nss-main, nss-pqc

```
AttributeError: 'SecretKey' object has no attribute 'derive_key'
```

**Classification:** pkcs11-check bug -- `SecretKey` missing `derive_key` method in python-pkcs11 fork.

#### `TestTLSNegativeAttributes::test_derive_without_derive_attr[TLS12_KEY_AND_MAC_DERIVE]`

**Providers (6):** kryoptic, kryoptic-fips, kryoptic-main, nss, nss-main, nss-pqc

```
AttributeError: 'SecretKey' object has no attribute 'derive_key'
```

**Classification:** pkcs11-check bug -- `SecretKey` missing `derive_key` method in python-pkcs11 fork.

#### `TestTLSNegativeAttributes::test_derive_without_derive_attr[TLS12_MASTER_KEY_DERIVE]`

**Providers (6):** kryoptic, kryoptic-fips, kryoptic-main, nss, nss-main, nss-pqc

```
AttributeError: 'SecretKey' object has no attribute 'derive_key'
```

**Classification:** pkcs11-check bug -- `SecretKey` missing `derive_key` method in python-pkcs11 fork.

#### `TestTLSNegativeAttributes::test_derive_without_derive_attr[TLS12_MASTER_KEY_DERIVE_DH]`

**Providers (6):** kryoptic, kryoptic-fips, kryoptic-main, nss, nss-main, nss-pqc

```
AttributeError: 'SecretKey' object has no attribute 'derive_key'
```

**Classification:** pkcs11-check bug -- `SecretKey` missing `derive_key` method in python-pkcs11 fork.

#### `TestTLSNegativeAttributes::test_mac_without_sign_attr[TLS_MAC]`

**Providers (6):** kryoptic, kryoptic-fips, kryoptic-main, nss, nss-main, nss-pqc

```
AttributeError: 'SecretKey' object has no attribute 'sign'
```

**Classification:** pkcs11-check bug -- TLS MAC test tries to call `sign()` on a `SecretKey` object.

### test_tookan.py

#### `TestSensitivePreservation::test_extractable_cannot_escalate_on_copy`

**Providers (5):** bouncyhsm, nss, nss-main, nss-pqc, tpm2

```
AssertionError: EXTRACTABLE escalated on copy - Tookan vulnerability
assert True is False
```

**Classification:** Security test (intentional) -- Tookan attack vector. Modules that allow EXTRACTABLE escalation on copy are vulnerable.

---

## Priority 3: Tests Failing on 2-4 Providers

**506 tests** fail across 2-4 providers. Grouped by test file.

### test_ckr_codes.py (2 tests)

- **`TestCKRPinErrors::test_ckr_pin_incorrect`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.UserTypeInvalid`
- **`TestCKRSessionErrors::test_ckr_user_already_logged_in`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.UserTypeInvalid`

### test_ckr_decrypt.py (1 tests)

- **`TestDecryptInitErrors::test_key_type_inconsistent`**
  - Fails on: bouncyhsm, tpm2
  - `Failed: C_DecryptInit(key_type_wrong_for_mechanism): got KeyHandleInvalid, not in acceptable set ['KeyTypeInconsistent', 'MechanismInvalid', 'KeyFunctionNotPermitted', 'FunctionFailed']`

### test_ckr_derive.py (1 tests)

- **`TestDeriveKeyErrors::test_key_type_inconsistent`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: C_DeriveKey(base_key_type_wrong_for_mechanism): got KeyHandleInvalid, not in acceptable set ['KeyTypeInconsistent', 'MechanismInvalid', 'KeyFunctionNotPermitted', 'MechanismParamInvalid', 'ArgumentsBad', 'FunctionFailed']`

### test_ckr_encrypt.py (1 tests)

- **`TestEncryptInitErrors::test_key_type_inconsistent`**
  - Fails on: bouncyhsm, tpm2
  - `Failed: C_EncryptInit(key_type_wrong_for_mechanism): got KeyHandleInvalid, not in acceptable set ['KeyTypeInconsistent', 'MechanismInvalid', 'KeyFunctionNotPermitted', 'FunctionFailed']`

### test_ckr_keygen.py (2 tests)

- **`TestGenerateKeyErrors::test_bad_key_size_non_standard`**
  - Fails on: bouncyhsm, tpm2
  - `Failed: C_GenerateKey(invalid_key_size): got TemplateInconsistent, not in acceptable set ['AttributeValueInvalid', 'KeySizeRange', 'MechanismInvalid', 'ArgumentsBad', 'TemplateIncomplete', 'FunctionFailed']`
- **`TestGenerateKeyErrors::test_bad_key_size_zero`**
  - Fails on: bouncyhsm, tpm2
  - `Failed: C_GenerateKey(invalid_key_size): got TemplateInconsistent, not in acceptable set ['AttributeValueInvalid', 'KeySizeRange', 'MechanismInvalid', 'ArgumentsBad', 'TemplateIncomplete', 'FunctionFailed']`

### test_ckr_raw_args_bad.py (6 tests)

- **`TestArgsBadNullPointers::test_decrypt_init_null_mechanism`**
  - Fails on: nss, nss-main, nss-pqc
  - `AssertionError: C_DecryptInit(NULL mech) subprocess error: Traceback (most recent call last):     File "<string>", line 37, in <module>   AssertionError: Got 0x00000071 assert 1 == 0`
- **`TestArgsBadNullPointers::test_derive_key_null_mechanism`**
  - Fails on: kryoptic, nss, nss-main, nss-pqc
  - `AssertionError: C_DeriveKey(NULL mech) subprocess error: Traceback (most recent call last):     File "<string>", line 24, in <module>   AssertionError: Got 0x00000082 assert 1 == 0`
- **`TestArgsBadNullPointers::test_encrypt_init_null_mechanism`**
  - Fails on: nss, nss-main, nss-pqc
  - `AssertionError: C_EncryptInit(NULL mech) subprocess error: Traceback (most recent call last):     File "<string>", line 39, in <module>   AssertionError: Got 0x00000071 assert 1 == 0`
- **`TestArgsBadNullPointers::test_sign_init_null_mechanism`**
  - Fails on: nss, nss-main, nss-pqc
  - `AssertionError: C_SignInit(NULL mech) subprocess error: Traceback (most recent call last):     File "<string>", line 23, in <module>   AssertionError: Got 0x00000071 assert 1 == 0`
- **`TestArgsBadNullPointers::test_verify_init_null_mechanism`**
  - Fails on: nss, nss-main, nss-pqc
  - `AssertionError: C_VerifyInit(NULL mech) subprocess error: Traceback (most recent call last):     File "<string>", line 23, in <module>   AssertionError: Got 0x00000071 assert 1 == 0`
- **`TestArgsBadNullPointers::test_wrap_key_null_mechanism`**
  - Fails on: kryoptic, tpm2
  - `AssertionError: C_WrapKey(NULL mech) subprocess error: s11/blob/1.9.1/docs/FAPI.md for more details   WARNING: Getting tokens from fapi backend failed.   Traceback (most recent call last):     File "<string>", line 25, in <module>   AssertionError: G`

### test_ckr_raw_attrs.py (3 tests)

- **`TestKeyFunctionNotPermitted::test_decrypt_not_permitted`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `AssertionError: Crash: iled: "fapi:Provisioning was not executed."   Please see https://github.com/tpm2-software/tpm2-pkcs11/blob/1.9.1/docs/FAPI.md for more details   WARNING: Getting tokens from fapi backend failed.   Traceback (most recent call la`
- **`TestKeyFunctionNotPermitted::test_encrypt_not_permitted`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `AssertionError: Crash: iled: "fapi:Provisioning was not executed."   Please see https://github.com/tpm2-software/tpm2-pkcs11/blob/1.9.1/docs/FAPI.md for more details   WARNING: Getting tokens from fapi backend failed.   Traceback (most recent call la`
- **`TestKeyFunctionNotPermitted::test_sign_not_permitted`**
  - Fails on: bouncyhsm, tpm2
  - `AssertionError: Crash: iled: "fapi:Provisioning was not executed."   Please see https://github.com/tpm2-software/tpm2-pkcs11/blob/1.9.1/docs/FAPI.md for more details   WARNING: Getting tokens from fapi backend failed.   Traceback (most recent call la`

### test_ckr_session.py (1 tests)

- **`TestLoginErrors::test_wrong_pin`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.UserTypeInvalid`

### test_ckr_sign.py (1 tests)

- **`TestSignInitErrors::test_key_type_inconsistent`**
  - Fails on: bouncyhsm, tpm2
  - `Failed: C_SignInit(key_type_wrong_for_mechanism): got KeyHandleInvalid, not in acceptable set ['KeyTypeInconsistent', 'MechanismInvalid', 'KeyFunctionNotPermitted', 'FunctionFailed']`

### test_ckr_universal.py (1 tests)

- **`TestUniversalRealTriggers::test_cryptoki_not_initialized_via_subprocess`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `AssertionError: Crash: Traceback (most recent call last):     File "<string>", line 10, in <module>   AssertionError: Got 0x00000000    assert 1 == 0  +  where 1 = CompletedProcess(args=['/app/.venv/bin/python', '-c', 'from pkcs11.raw import RawPKCS1`

### test_ckr_verify.py (1 tests)

- **`TestVerifyInitErrors::test_key_type_inconsistent`**
  - Fails on: bouncyhsm, tpm2
  - `Failed: C_VerifyInit(key_type_wrong_for_mechanism): got KeyHandleInvalid, not in acceptable set ['KeyTypeInconsistent', 'MechanismInvalid', 'KeyFunctionNotPermitted', 'FunctionFailed']`

### test_ckr_wrap.py (1 tests)

- **`TestWrapKeyErrors::test_key_not_extractable`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Should have rejected wrapping non-extractable key`

### test_access.py (2 tests)

- **`TestMultipleSessions::test_session_object_visible_in_other_session`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestSessionTypes::test_ro_session_can_create_session_objects`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`

### test_access_control.py (8 tests)

- **`TestCopyObject::test_copy_changes_extractable`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.AttributeTypeInvalid`
- **`TestCopyObject::test_copy_session_object_stays_session`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.AttributeTypeInvalid`
- **`TestCopyObject::test_copy_token_object_stays_token`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestCopyObject::test_copy_with_modified_label`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.AttributeTypeInvalid`
- **`TestCopyObject::test_non_copyable_key_rejected`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `Failed: DID NOT RAISE any of (<class 'pkcs11.exceptions.ActionProhibited'>, <class 'pkcs11.exceptions.AttributeTypeInvalid'>, <class 'pkcs11.exceptions.AttributeValueInvalid'>, <class 'pkcs11.exceptions.TemplateInconsistent'>)`
- **`TestCopyableAttribute::test_copyable_key_can_be_copied`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.AttributeTypeInvalid`
- **`TestCopyableAttribute::test_default_key_copyable_flag`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.AttributeTypeInvalid`
- **`TestPrivateAttribute::test_non_private_object_visible_without_login`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`

### test_access_levels.py (1 tests)

- **`TestTrustedAttribute::test_wrap_with_trusted_rejects_untrusted`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: DID NOT RAISE any of (<class 'pkcs11.exceptions.ActionProhibited'>, <class 'pkcs11.exceptions.KeyNotWrappable'>, <class 'pkcs11.exceptions.PKCS11Error'>)`

### test_aead.py (4 tests)

- **`TestAESGCMCrossVerify::test_gcm_128_encrypt_crossverify`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.BufferTooSmall`
- **`TestAESGCMCrossVerify::test_gcm_256_encrypt_crossverify`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.BufferTooSmall`
- **`TestAESGCMProperties::test_gcm_different_nonces_different_ct`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestAESGCMProperties::test_gcm_roundtrip`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`

### test_aes_modes.py (5 tests)

- **`TestAESCTR::test_aes_ctr_different_keys`**
  - Fails on: bouncyhsm, opencryptoki, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestAESCTR::test_aes_ctr_non_block_aligned`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestAESCTR::test_aes_ctr_roundtrip`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestAESXCBCMAC::test_aes_xcbc_mac_96_sign_verify`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.KeyTypeInconsistent`
- **`TestAESXCBCMAC::test_aes_xcbc_mac_sign_verify`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.KeyTypeInconsistent`

### test_attribute_defaults.py (4 tests)

- **`TestKeyPairDefaults::test_private_key_extractable`**
  - Fails on: nss, nss-main, nss-pqc, opencryptoki
  - `assert True is False`
- **`TestKeyPairDefaults::test_private_key_local`**
  - Fails on: nss, nss-main, nss-pqc
  - `assert False is True`
- **`TestKeyPairDefaults::test_public_key_local`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestSecretKeyDefaults::test_local_is_true`**
  - Fails on: nss, nss-main, nss-pqc
  - `assert False is True`

### test_attribute_enforcement.py (5 tests)

- **`TestAllowedMechanisms::test_allowed_mechanism_restricts_usage`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: DID NOT RAISE any of (<class 'pkcs11.exceptions.MechanismInvalid'>, <class 'pkcs11.exceptions.PKCS11Error'>)`
- **`TestCheckValue::test_generated_key_has_check_value`**
  - Fails on: opencryptoki, tpm2
  - `AssertionError: Expected 3-byte KCV, got 0 bytes assert 0 == 3  +  where 0 = len(b'')`
- **`TestDestroyable::test_destroyable_false_blocks_destroy`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `Failed: DID NOT RAISE <class 'pkcs11.exceptions.ActionProhibited'>`
- **`TestKeyGenMechanism::test_key_gen_mechanism_read_only`**
  - Fails on: bouncyhsm, tpm2
  - `Failed: DID NOT RAISE any of (<class 'pkcs11.exceptions.AttributeReadOnly'>, <class 'pkcs11.exceptions.AttributeTypeInvalid'>, <class 'pkcs11.exceptions.AttributeValueInvalid'>, <class 'pkcs11.exceptions.ActionProhibited'>)`
- **`TestWrapWithTrusted::test_wrap_with_trusted_rejects_untrusted_wrapper`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: DID NOT RAISE any of (<class 'pkcs11.exceptions.ActionProhibited'>, <class 'pkcs11.exceptions.KeyNotWrappable'>, <class 'pkcs11.exceptions.PKCS11Error'>)`

### test_buffers.py (2 tests)

- **`TestEncryptBufferSizes::test_1mb`**
  - Fails on: bouncyhsm, tpm2
  - `Fatal Python error: Segmentation fault  Current thread 0x00007f7057ebe300 (most recent call first):   File "/app/python-pkcs11/pkcs11/types.py", line 1296 in encrypt   File "/app/src/pkcs11_check/testcases/test_buffers.py", line 57 in test_1mb   File`
- **`TestSignBufferSizes::test_sign_empty`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`

### test_camellia.py (13 tests)

- **`TestCamelliaEncryption::test_camellia_cbc_different_ivs`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`
- **`TestCamelliaEncryption::test_camellia_cbc_pad_different_keys`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`
- **`TestCamelliaEncryption::test_camellia_cbc_pad_roundtrip`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`
- **`TestCamelliaEncryption::test_camellia_cbc_roundtrip`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`
- **`TestCamelliaEncryption::test_camellia_ecb_different_keys`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`
- **`TestCamelliaEncryption::test_camellia_ecb_roundtrip`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`
- **`TestCamelliaKeyGen::test_camellia_key_gen_128`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`
- **`TestCamelliaKeyGen::test_camellia_key_gen_192`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`
- **`TestCamelliaKeyGen::test_camellia_key_gen_256`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`
- **`TestCamelliaKeyGen::test_camellia_key_gen_not_null`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`
- **`TestCamelliaMAC::test_camellia_mac_different_keys`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`
- **`TestCamelliaMAC::test_camellia_mac_general_sign_verify`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`
- **`TestCamelliaMAC::test_camellia_mac_sign_verify`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`

### test_concurrent_sessions.py (5 tests)

- **`TestConcurrentDataObjects::test_data_object_visible_across_sessions`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestConcurrentObjectCreation::test_create_in_both_sessions_no_conflict`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestConcurrentObjectCreation::test_rapid_create_destroy_cycle`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestConcurrentSessions::test_destroy_in_one_session_reflected_in_other`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestConcurrentSessions::test_two_sessions_see_same_token_object`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`

### test_crossverify.py (1 tests)

- **`TestRSAKeySizeCrossVerify::test_rsa_2048_sha1`**
  - Fails on: kryoptic-fips, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`

### test_cve_regression.py (2 tests)

- **`TestBoundaryLengthCrypto::test_aes_ecb_boundary_lengths`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestInvalidECCurve::test_import_ec_key_with_bad_oid`**
  - Fails on: nss, nss-main, nss-pqc, opencryptoki
  - `pkcs11.exceptions.DomainParamsInvalid`

### test_data_objects.py (1 tests)

- **`TestDataObjectToken::test_token_data_object_survives_session`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.AttributeValueInvalid`

### test_ecdsa_extended.py (8 tests)

- **`TestECDSAPrehash::test_nondeterministic[SHA1]`**
  - Fails on: kryoptic-fips, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestECDSAPrehash::test_sign_verify_roundtrip[SHA1]`**
  - Fails on: kryoptic-fips, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestECDSAPrehash::test_tampered_data_fails[SHA1]`**
  - Fails on: kryoptic, kryoptic-fips, kryoptic-main, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestECDSAPrehash::test_tampered_data_fails[SHA224]`**
  - Fails on: kryoptic, kryoptic-fips, kryoptic-main
  - `pkcs11.exceptions.DeviceError`
- **`TestECDSAPrehash::test_tampered_data_fails[SHA3-224]`**
  - Fails on: kryoptic, kryoptic-fips, kryoptic-main
  - `pkcs11.exceptions.DeviceError`
- **`TestECDSAPrehash::test_tampered_data_fails[SHA3-256]`**
  - Fails on: kryoptic, kryoptic-fips, kryoptic-main
  - `pkcs11.exceptions.DeviceError`
- **`TestECDSAPrehash::test_tampered_data_fails[SHA3-384]`**
  - Fails on: kryoptic, kryoptic-fips, kryoptic-main
  - `pkcs11.exceptions.DeviceError`
- **`TestECDSAPrehash::test_tampered_data_fails[SHA3-512]`**
  - Fails on: kryoptic, kryoptic-fips, kryoptic-main
  - `pkcs11.exceptions.DeviceError`

### test_eddsa.py (7 tests)

- **`TestEdDSACrossVerify::test_sign_p11_verify_crypto`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad`
- **`TestEdDSASignVerify::test_deterministic_signatures`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad`
- **`TestEdDSASignVerify::test_different_data_different_signatures`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad`
- **`TestEdDSASignVerify::test_different_keys_different_signatures`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad`
- **`TestEdDSASignVerify::test_sign_verify_roundtrip`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad`
- **`TestEdDSASignVerify::test_signature_length`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `pkcs11.exceptions.GeneralError`
- **`TestEdDSASignVerify::test_wrong_data_fails`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad`

### test_encrypt.py (1 tests)

- **`TestRSAEncryption::test_rsa_pkcs_roundtrip`**
  - Fails on: kryoptic-fips, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`

### test_fuzz.py (2 tests)

- **`TestHMACFuzz::test_hmac_deterministic`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.GeneralError Falsifying example: test_hmac_deterministic(     self=<pkcs11_check.testcases.test_fuzz.TestHMACFuzz object at 0x7d6460a434a0>,     p11_session=<pkcs11._pkcs11.Session object at 0x7d6460e517c0>,     data=b'',  # or any`
- **`TestHMACFuzz::test_hmac_sha256_cross_verify`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.GeneralError Falsifying example: test_hmac_sha256_cross_verify(     self=<pkcs11_check.testcases.test_fuzz.TestHMACFuzz object at 0x7d6460a43170>,     p11_session=<pkcs11._pkcs11.Session object at 0x7d6460e509c0>,     data=b'',  # o`

### test_hkdf_extended.py (4 tests)

- **`TestHKDFData::test_hkdf_data_derive`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestHKDFData::test_hkdf_data_deterministic`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestHKDFData::test_hkdf_data_different_info_different_output`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestHKDFKeyGen::test_hkdf_key_gen_usable_for_derive`**
  - Fails on: kryoptic, kryoptic-fips, kryoptic-main
  - `pkcs11.exceptions.AttributeValueInvalid`

### test_interop.py (2 tests)

- **`TestAESInterop::test_aes_gcm_encrypt_p11_decrypt_crypto`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.BufferTooSmall`
- **`TestRSAInterop::test_rsa_multi_hash_interop[SHA1]`**
  - Fails on: kryoptic-fips, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`

### test_kat.py (1 tests)

- **`TestSHA224KAT::test_sha224_kat[d14a028c2a3a2bc9]`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.MechanismInvalid`

### test_kdf.py (2 tests)

- **`TestECDHDerive::test_ecdh_different_peers_different_secrets`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.MechanismParamInvalid`
- **`TestECDHDerive::test_ecdh_shared_secret_agreement`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.MechanismParamInvalid`

### test_kem.py (10 tests)

- **`TestMLKEMCiphertextSize::test_ciphertext_size[ML_KEM_1024-1568]`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.BufferTooSmall`
- **`TestMLKEMCiphertextSize::test_ciphertext_size[ML_KEM_512-768]`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.BufferTooSmall`
- **`TestMLKEMCiphertextSize::test_ciphertext_size[ML_KEM_768-1088]`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.BufferTooSmall`
- **`TestMLKEMEncapsulateDecapsulate::test_decapsulate_with_wrong_key_fails_or_differs`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.BufferTooSmall`
- **`TestMLKEMEncapsulateDecapsulate::test_encapsulate_ciphertext_nonzero`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.BufferTooSmall`
- **`TestMLKEMEncapsulateDecapsulate::test_encapsulate_decapsulate_shared_secret_matches`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.BufferTooSmall`
- **`TestMLKEMEncapsulateDecapsulate::test_encapsulate_returns_ciphertext_and_key`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.BufferTooSmall`
- **`TestMLKEMEncapsulateDecapsulate::test_two_encapsulations_produce_different_ciphertexts`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.BufferTooSmall`
- **`TestMLKEMKeyDerivation::test_parameter_set_produces_correct_ciphertext_size[2-1088]`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.BufferTooSmall`
- **`TestMLKEMKeyDerivation::test_parameter_set_produces_correct_ciphertext_size[3-1568]`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.BufferTooSmall`

### test_key_flags.py (2 tests)

- **`TestLocalFlag::test_generated_key_is_local`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestLocalFlag::test_generated_rsa_keypair_is_local`**
  - Fails on: nss, nss-main, nss-pqc
  - `AssertionError: CKA_LOCAL=False on generated public key - spec requires LOCAL=TRUE for generated keys assert False is True`

### test_keymgmt.py (1 tests)

- **`TestKeyWrapUnwrap::test_wrap_unwrap_roundtrip`**
  - Fails on: bouncyhsm, opencryptoki, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`

### test_large_objects.py (2 tests)

- **`TestLargeEncryption::test_encrypt_1mb_aes_cbc`**
  - Fails on: bouncyhsm, tpm2
  - `Fatal Python error: Segmentation fault  Current thread 0x000074755735d300 (most recent call first):   File "/app/python-pkcs11/pkcs11/types.py", line 1296 in encrypt   File "/app/src/pkcs11_check/testcases/test_large_objects.py", line 93 in test_encr`
- **`TestLargeRandomGeneration::test_generate_100kb_random`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad`

### test_mechanism_fuzz.py (2 tests)

- **`TestAESParameterFuzz::test_aes_cbc_bad_iv[17-bytes]`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `Failed: DID NOT RAISE any of (<class 'pkcs11.exceptions.PKCS11Error'>, <class 'ValueError'>)`
- **`TestAESParameterFuzz::test_aes_cbc_bad_iv[256-bytes]`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `Failed: DID NOT RAISE any of (<class 'pkcs11.exceptions.PKCS11Error'>, <class 'ValueError'>)`

### test_metamorphic.py (1 tests)

- **`TestRoundTripInvariants::test_wrap_unwrap_preserves_material`**
  - Fails on: bouncyhsm, opencryptoki, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`

### test_misc_kdf.py (2 tests)

- **`TestExtractKeyFromKey::test_extract_at_byte_boundary_offset`**
  - Fails on: bouncyhsm, kryoptic, kryoptic-fips, kryoptic-main
  - `Fatal Python error: Aborted  Current thread 0x0000750607391b80 (most recent call first):   File "/app/src/pkcs11_check/testcases/test_misc_kdf.py", line 574 in test_extract_at_byte_boundary_offset   File "/app/.venv/lib64/python3.12/site-packages/_py`
- **`TestExtractKeyFromKey::test_extract_from_offset_zero`**
  - Fails on: kryoptic, kryoptic-fips, kryoptic-main
  - `Fatal Python error: Aborted  Current thread 0x0000775410181b80 (most recent call first):   File "/app/src/pkcs11_check/testcases/test_misc_kdf.py", line 537 in test_extract_from_offset_zero   File "/app/.venv/lib64/python3.12/site-packages/_pytest/py`

### test_multipart.py (1 tests)

- **`TestMultiPartSign::test_rsa_sign_empty`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`

### test_object_visibility.py (16 tests)

- **`TestCrossSessionDestruction::test_destroy_in_a_gone_in_b`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestCrossSessionModification::test_modify_in_session_a_read_in_session_b`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestCrossSessionModification::test_modify_value_cross_session`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestPrivateVisibility::test_private_object_hidden_without_login`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestPrivateVisibility::test_private_object_visible_after_login`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestPrivateVisibility::test_public_object_visible_without_login`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestTokenObjectImmediateVisibility::test_destroyed_token_object_gone_immediately`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestTokenObjectImmediateVisibility::test_multiple_token_objects_all_visible`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestTokenObjectImmediateVisibility::test_token_key_usable_immediately`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestTokenObjectImmediateVisibility::test_token_object_visible_immediately`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestTokenObjectPersistence::test_token_data_object_survives_session`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestTokenObjectPersistence::test_token_object_survives_session_close`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestTokenObjectPersistence::test_token_object_value_preserved`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestTokenPrivateInteraction::test_private_session_obj_visible_same_session`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestTokenPrivateInteraction::test_private_token_obj_persists_with_login`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestTokenPrivateInteraction::test_public_token_obj_persists`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`

### test_operation_state.py (2 tests)

- **`TestDigestStateRoundTrip::test_digest_state_cross_session`**
  - Fails on: kryoptic-fips, nss, nss-main, nss-pqc
  - `AssertionError: Expected CROSS_SESSION_ACCEPTED or CROSS_SESSION_REJECTED; stdout='STATE_SAVED:179\nCROSS_SESSION_ACCEPTED' assert ('CROSS_SESSION_ACCEPTED' in {'STATE_SAVED': '179'} or 'CROSS_SESSION_REJECTED' in {'STATE_SAVED': '179'})`
- **`TestEncryptStateRoundTrip::test_encrypt_state_same_session`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Subprocess failed: FATAL:GetState_len:0x00000091`

### test_protocol_edge_cases.py (1 tests)

- **`TestResourceExhaustion::test_generate_random_large`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad`

### test_rng.py (1 tests)

- **`TestRNGStatistical::test_seed_random`**
  - Fails on: bouncyhsm, opencryptoki
  - `pkcs11.exceptions.RandomSeedNotSupported`

### test_ro_session.py (1 tests)

- **`TestSessionObjectLifecycle::test_token_object_persists_after_close`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`

### test_ro_session_restrictions.py (12 tests)

- **`TestROCryptoOperations::test_encrypt_decrypt_session_key_in_ro`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestROCryptoOperations::test_sign_verify_session_key_in_ro`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestROCryptoOperations::test_verify_token_key_in_ro`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.TokenWriteProtected`
- **`TestROExactCKR::test_destroy_token_object_returns_session_read_only`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestROSessionObjectsAllowed::test_create_session_object_in_ro_succeeds`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.SessionReadOnly`
- **`TestROSessionObjectsAllowed::test_generate_key_token_false_in_ro_succeeds`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestROSessionObjectsAllowed::test_generate_keypair_session_in_ro_succeeds`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.SessionReadOnly`
- **`TestROTokenObjectMutation::test_copy_token_object_in_ro_as_token_fails`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestROTokenObjectMutation::test_destroy_token_object_in_ro_fails`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestROTokenObjectMutation::test_set_attribute_token_object_in_ro_fails`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestROWrapUnwrapRestrictions::test_unwrap_to_session_object_in_ro_succeeds`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestROWrapUnwrapRestrictions::test_unwrap_to_token_object_in_ro_fails`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`

### test_rsa_key_wrapping.py (5 tests)

- **`TestRSAOAEPWrap::test_wrap_unwrap_oaep`**
  - Fails on: opencryptoki, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestRSAPKCSWrap::test_wrap_unwrap_aes128`**
  - Fails on: kryoptic-fips, opencryptoki, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestRSAPKCSWrap::test_wrap_unwrap_aes256`**
  - Fails on: kryoptic-fips, opencryptoki, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`
- **`TestWrappedKeyUsability::test_non_extractable_key_cannot_be_wrapped`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `Failed: DID NOT RAISE <class 'Exception'>`
- **`TestWrappedKeyUsability::test_unwrapped_key_encrypts`**
  - Fails on: kryoptic-fips, opencryptoki, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`

### test_salsa20.py (4 tests)

- **`TestChaCha20Standalone::test_chacha20_different_block_counters_differ`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`
- **`TestChaCha20Standalone::test_chacha20_different_nonces_differ`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`
- **`TestChaCha20Standalone::test_chacha20_encrypt_decrypt`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`
- **`TestChaCha20Standalone::test_chacha20_key_gen`**
  - Fails on: bouncyhsm, nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.`

### test_session_info.py (1 tests)

- **`TestSessionInfo::test_ro_session_cannot_generate_token_objects`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`

### test_session_state_machine.py (3 tests)

- **`TestConcurrentSessionLogin::test_login_in_one_session_visible_in_another`**
  - Fails on: bouncyhsm, tpm2
  - `AssertionError: Session B cannot see private object - login not shared assert 0 >= 1  +  where 0 = len([])`
- **`TestROvsRWSessionState::test_ro_session_can_create_session_objects`**
  - Fails on: bouncyhsm, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`
- **`TestSessionContextManager::test_context_manager_closes_session`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: DID NOT RAISE any of (<class 'pkcs11.exceptions.SessionClosed'>, <class 'pkcs11.exceptions.SessionHandleInvalid'>, <class 'AttributeError'>)`

### test_sign.py (1 tests)

- **`TestRSASignature::test_rsa_hash_mechanisms[SHA1]`**
  - Fails on: kryoptic-fips, tpm2
  - `pkcs11.exceptions.AttributeValueInvalid`

### test_sign_recover.py (3 tests)

- **`TestSignRecover::test_sign_recover_produces_output`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `Failed: Subprocess failed: FATAL:GenerateKeyPair:0x00000013`
- **`TestSignRecover::test_sign_recover_wrong_data_length`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `Failed: Subprocess failed: FATAL:GenerateKeyPair:0x00000013`
- **`TestSignRecover::test_verify_recover_round_trip`**
  - Fails on: nss, nss-main, nss-pqc, tpm2
  - `Failed: Subprocess failed: FATAL:GenerateKeyPair:0x00000013`

### test_ssl3.py (4 tests)

- **`TestSSL3Mac::test_md5_mac_sign`**
  - Fails on: nss, nss-main, nss-pqc
  - `AssertionError: Expected 16-byte MD5 MAC, got 128 assert 128 == 16  +  where 128 = len(b'\xf8\xad\xc4\xaa)\x94\xad"\x96\xecu\x9d\x1a2\x1b\x0bP~\xc7\xb2\xfd\x7f\x00\x00Pe\xd4\x88j_\x00\x00\x00\x00\x00\x00\x...\x00\x00\xf0\x7f\xc7\xb2\xfd\x7f\x00\x00p\`
- **`TestSSL3Mac::test_sha1_mac_sign`**
  - Fails on: nss, nss-main, nss-pqc
  - `AssertionError: Expected 20-byte SHA1 MAC, got 160 assert 160 == 20  +  where 160 = len(b'\xe9\xaf73\rO\xac \xf2\x99C\xdc\xd6\xcd\xd5\xf4\xfd\x92#\xbb\xfd\x7f\x00\x00 \x84\xe6\x88j_\x00\x00\x88\x07=\x12\x00...00@\x7f\xc7\xb2\xfd\x7f\x00\x00<\xa7\x9b\`
- **`TestSSL3MasterKeyDerive::test_derive_master_secret`**
  - Fails on: nss, nss-main, nss-pqc, opencryptoki
  - `Fatal Python error: Segmentation fault  Current thread 0x00007c0e26bb0b80 [python] (most recent call first):   File "/app/src/pkcs11_check/testcases/test_ssl3.py", line 190 in test_derive_master_secret   File "/app/.venv/lib64/python3.14/site-package`
- **`TestSSL3MasterKeyDeriveDH::test_derive_master_secret_dh`**
  - Fails on: nss, nss-main, nss-pqc
  - `Fatal Python error: Segmentation fault  Current thread 0x0000781a9125fb80 (most recent call first):   File "/app/src/pkcs11_check/testcases/test_ssl3.py", line 239 in test_derive_master_secret_dh   File "/app/.venv/lib64/python3.12/site-packages/_pyt`

### test_threading.py (1 tests)

- **`TestThreadedOperations::test_threaded_keygen_destroy`**
  - Fails on: softhsm2-main, tpm2
  - `pkcs11.exceptions.FunctionNotSupported`

### test_tls12.py (12 tests)

- **`TestTLS12KDF::test_tls12_kdf`**
  - Fails on: kryoptic, kryoptic-fips, kryoptic-main
  - `ValueError: need more than 3 values to unpack`
- **`TestTLS12KDF::test_tls_kdf`**
  - Fails on: kryoptic, kryoptic-fips, kryoptic-main
  - `ValueError: need more than 3 values to unpack`
- **`TestTLS12KeyAndMacDerive::test_key_and_mac_derive`**
  - Fails on: nss, nss-main, nss-pqc
  - `pkcs11.exceptions.ObjectHandleInvalid`
- **`TestTLS12Mac::test_tls12_mac`**
  - Fails on: kryoptic, kryoptic-fips, kryoptic-main
  - `TypeError: keywords must be strings`
- **`TestTLSNegativeAttributes::test_derive_without_derive_attr[SSL3_KEY_AND_MAC_DERIVE]`**
  - Fails on: nss, nss-main, nss-pqc, opencryptoki
  - `AttributeError: 'SecretKey' object has no attribute 'derive_key'`
- **`TestTLSNegativeAttributes::test_derive_without_derive_attr[SSL3_MASTER_KEY_DERIVE]`**
  - Fails on: nss, nss-main, nss-pqc, opencryptoki
  - `AttributeError: 'SecretKey' object has no attribute 'derive_key'`
- **`TestTLSNegativeAttributes::test_derive_without_derive_attr[SSL3_MASTER_KEY_DERIVE_DH]`**
  - Fails on: nss, nss-main, nss-pqc
  - `AttributeError: 'SecretKey' object has no attribute 'derive_key'`
- **`TestTLSNegativeAttributes::test_derive_without_derive_attr[TLS12_KEY_SAFE_DERIVE]`**
  - Fails on: kryoptic, kryoptic-fips, kryoptic-main
  - `AttributeError: 'SecretKey' object has no attribute 'derive_key'`
- **`TestTLSNegativeAttributes::test_derive_without_derive_attr[TLS_KEY_AND_MAC_DERIVE]`**
  - Fails on: nss, nss-main, nss-pqc
  - `AttributeError: 'SecretKey' object has no attribute 'derive_key'`
- **`TestTLSNegativeAttributes::test_derive_without_derive_attr[TLS_MASTER_KEY_DERIVE]`**
  - Fails on: nss, nss-main, nss-pqc
  - `AttributeError: 'SecretKey' object has no attribute 'derive_key'`
- **`TestTLSNegativeAttributes::test_derive_without_derive_attr[TLS_MASTER_KEY_DERIVE_DH]`**
  - Fails on: nss, nss-main, nss-pqc
  - `AttributeError: 'SecretKey' object has no attribute 'derive_key'`
- **`TestTLSNegativeAttributes::test_mac_without_sign_attr[TLS12_MAC]`**
  - Fails on: kryoptic, kryoptic-fips, kryoptic-main
  - `AttributeError: 'SecretKey' object has no attribute 'sign'`

### test_token_flags.py (2 tests)

- **`TestSlotInfo::test_slot_flags_are_valid`**
  - Fails on: nss, nss-main, nss-pqc
  - `AssertionError: Slot 1 flags contain unknown bits: 0x00000008 (flags=0x00000009) assert 8 == 0`
- **`TestTokenFlags::test_user_pin_initialized_flag`**
  - Fails on: nss, nss-main, nss-pqc
  - `AssertionError: CKF_USER_PIN_INITIALIZED must be set; flags=<TokenFlag.RNG|WRITE_PROTECTED|DUAL_CRYPTO_OPERATIONS|TOKEN_INITIALIZED: 1539> assert <TokenFlag.USER_PIN_INITIALIZED: 8> in <TokenFlag.RNG|WRITE_PROTECTED|DUAL_CRYPTO_OPERATIONS|TOKEN_INITI`

### test_wycheproof_dsa.py (296 tests)

- **`test_dsa[dsa_2048_224_sha224_test.json:tc2-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc2-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc286-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc286-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc287-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc287-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc288-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc288-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc289-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc289-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc290-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc290-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc291-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc291-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc292-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc292-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc293-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc293-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc294-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc294-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc295-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc295-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc296-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc296-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc297-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc297-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc298-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc298-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc299-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc299-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc300-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc300-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc301-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc301-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc302-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc302-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc303-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc303-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc304-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc304-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc305-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc305-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc306-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc306-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc307-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc307-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc308-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc308-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc309-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc309-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc310-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc310-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc311-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc311-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc312-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc312-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc313-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc313-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc314-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc314-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc315-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc315-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc316-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc316-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc317-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc317-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc318-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc318-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc319-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc319-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc320-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc320-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc321-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc321-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc322-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc322-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc323-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc323-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc324-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc324-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc325-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc325-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc326-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc326-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc327-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc327-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc328-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc328-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc329-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc329-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc330-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc330-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc331-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc331-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc332-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc332-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc333-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc333-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc334-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc334-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc335-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc335-valid rejected`
- **`test_dsa[dsa_2048_224_sha224_test.json:tc336-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha224_test.json:tc336-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc2-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc2-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc286-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc286-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc287-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc287-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc288-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc288-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc289-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc289-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc290-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc290-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc291-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc291-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc292-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc292-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc293-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc293-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc294-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc294-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc295-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc295-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc296-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc296-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc297-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc297-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc298-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc298-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc299-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc299-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc300-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc300-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc301-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc301-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc302-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc302-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc303-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc303-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc304-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc304-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc305-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc305-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc306-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc306-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc307-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc307-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc308-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc308-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc309-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc309-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc310-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc310-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc311-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc311-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc312-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc312-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc313-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc313-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc314-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc314-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc315-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc315-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc316-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc316-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc317-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc317-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc318-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc318-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc319-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc319-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc320-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc320-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc321-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc321-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc322-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc322-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc323-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc323-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc324-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc324-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc325-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc325-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc326-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc326-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc327-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc327-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc328-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc328-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc329-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc329-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc330-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc330-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc331-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc331-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc332-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc332-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc333-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc333-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc334-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc334-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc335-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc335-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc336-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc336-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc337-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc337-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc338-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc338-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc339-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc339-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc340-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc340-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc341-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc341-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc342-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc342-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc343-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc343-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc344-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc344-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc345-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc345-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc346-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc346-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc347-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc347-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc348-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc348-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc349-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc349-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc350-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc350-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc351-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc351-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc352-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc352-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc353-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc353-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc354-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc354-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc355-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc355-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc356-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc356-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc357-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc357-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc358-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc358-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc359-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc359-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc360-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc360-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc361-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc361-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc362-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc362-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc363-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc363-valid rejected`
- **`test_dsa[dsa_2048_224_sha256_test.json:tc364-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_224_sha256_test.json:tc364-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc2-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc2-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc286-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc286-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc287-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc287-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc288-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc288-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc289-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc289-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc290-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc290-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc291-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc291-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc292-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc292-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc293-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc293-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc294-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc294-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc295-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc295-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc296-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc296-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc297-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc297-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc298-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc298-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc299-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc299-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc300-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc300-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc301-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc301-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc302-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc302-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc303-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc303-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc304-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc304-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc305-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc305-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc306-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc306-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc307-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc307-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc308-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc308-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc309-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc309-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc310-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc310-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc311-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc311-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc312-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc312-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc313-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc313-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc314-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc314-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc315-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc315-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc316-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc316-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc317-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc317-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc318-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc318-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc319-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc319-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc320-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc320-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc321-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc321-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc322-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc322-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc323-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc323-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc324-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc324-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc325-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc325-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc326-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc326-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc327-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc327-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc328-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc328-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc329-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc329-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc330-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc330-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc331-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc331-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc332-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc332-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc333-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc333-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc334-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc334-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc335-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc335-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc336-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc336-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc337-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc337-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc338-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc338-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc339-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc339-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc340-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc340-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc341-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc341-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc342-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc342-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc343-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc343-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc344-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc344-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc345-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc345-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc346-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc346-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc347-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc347-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc348-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc348-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc349-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc349-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc350-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc350-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc351-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc351-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc352-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc352-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc353-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc353-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc354-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc354-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc355-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc355-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc356-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc356-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc357-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc357-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc358-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc358-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc359-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc359-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc360-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc360-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc361-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc361-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc362-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc362-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc363-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc363-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc364-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc364-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc365-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc365-valid rejected`
- **`test_dsa[dsa_2048_256_sha256_test.json:tc366-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_2048_256_sha256_test.json:tc366-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc2-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc2-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc286-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc286-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc287-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc287-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc288-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc288-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc289-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc289-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc290-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc290-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc291-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc291-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc292-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc292-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc293-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc293-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc294-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc294-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc295-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc295-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc296-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc296-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc297-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc297-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc298-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc298-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc299-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc299-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc300-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc300-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc301-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc301-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc302-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc302-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc303-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc303-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc304-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc304-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc305-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc305-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc306-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc306-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc307-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc307-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc308-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc308-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc309-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc309-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc310-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc310-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc311-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc311-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc312-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc312-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc313-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc313-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc314-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc314-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc315-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc315-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc316-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc316-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc317-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc317-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc318-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc318-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc319-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc319-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc320-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc320-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc321-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc321-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc322-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc322-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc323-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc323-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc324-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc324-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc325-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc325-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc326-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc326-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc327-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc327-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc328-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc328-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc329-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc329-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc330-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc330-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc331-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc331-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc332-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc332-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc333-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc333-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc334-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc334-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc335-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc335-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc336-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc336-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc337-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc337-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc338-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc338-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc339-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc339-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc340-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc340-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc341-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc341-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc342-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc342-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc343-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc343-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc344-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc344-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc345-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc345-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc346-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc346-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc347-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc347-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc348-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc348-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc349-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc349-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc350-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc350-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc351-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc351-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc352-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc352-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc353-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc353-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc354-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc354-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc355-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc355-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc356-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc356-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc357-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc357-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc358-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc358-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc359-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc359-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc360-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc360-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc361-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc361-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc362-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc362-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc363-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc363-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc364-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc364-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc365-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc365-valid rejected`
- **`test_dsa[dsa_3072_256_sha256_test.json:tc366-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid DSA sig dsa_3072_256_sha256_test.json:tc366-valid rejected`

### test_wycheproof_ecdsa.py (18 tests)

- **`test_ecdsa_wycheproof[ecdsa_secp160k1_sha256_test.json:tc351-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp160k1_sha256_test.json:tc351-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp160k1_sha256_test.json:tc441-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp160k1_sha256_test.json:tc441-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp160r1_sha256_test.json:tc351-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp160r1_sha256_test.json:tc351-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp160r1_sha256_test.json:tc444-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp160r1_sha256_test.json:tc444-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp160r2_sha256_test.json:tc352-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp160r2_sha256_test.json:tc352-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp160r2_sha256_test.json:tc417-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp160r2_sha256_test.json:tc417-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp160r2_sha256_test.json:tc418-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp160r2_sha256_test.json:tc418-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp160r2_sha256_test.json:tc444-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp160r2_sha256_test.json:tc444-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp224k1_sha224_test.json:tc322-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp224k1_sha224_test.json:tc322-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp224k1_sha224_test.json:tc386-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp224k1_sha224_test.json:tc386-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp224k1_sha224_test.json:tc387-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp224k1_sha224_test.json:tc387-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp224k1_sha224_test.json:tc388-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp224k1_sha224_test.json:tc388-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp224k1_sha224_test.json:tc412-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp224k1_sha224_test.json:tc412-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp224k1_sha256_test.json:tc352-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp224k1_sha256_test.json:tc352-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp224k1_sha256_test.json:tc416-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp224k1_sha256_test.json:tc416-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp224k1_sha256_test.json:tc417-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp224k1_sha256_test.json:tc417-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp224k1_sha256_test.json:tc418-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp224k1_sha256_test.json:tc418-valid`
- **`test_ecdsa_wycheproof[ecdsa_secp224k1_sha256_test.json:tc442-valid]`**
  - Fails on: bouncyhsm, softhsm2, softhsm2-main
  - `Failed: Cannot decode valid DER sig for ecdsa_secp224k1_sha256_test.json:tc442-valid`

### test_wycheproof_mlkem.py (1 tests)

- **`test_mlkem_decaps[mlkem_512_semi_expanded_decaps_test.json:tc1-valid]`**
  - Fails on: nss, nss-main, nss-pqc
  - `Failed: Valid ML-KEM decaps failed: mlkem_512_semi_expanded_decaps_test.json:tc1-valid`

---

## Priority 4: Provider-Specific Failures

Tests that fail on only one provider (excluding pkcs11-mock).

### bouncyhsm (110 failures, 5 crashes)

Crashes covered in Priority 1.

**test_access_levels.py** (1 tests):
- `TestUserSessionCapabilities::test_user_cannot_login_as_so`: pkcs11.exceptions.PinIncorrect

**test_attribute_enforcement.py** (1 tests):
- `TestKeyGenMechanism::test_imported_key_has_unavailable`: AssertionError: Expected CK_UNAVAILABLE_INFORMATION, got 0x1080 assert <Mechanism.AES_KEY_GEN> in (4294967295, 18446744073709551615)

**test_attribute_fuzz.py** (3 tests):
- `TestMalformedAttributes::test_empty_value_on_aes_key`: pkcs11.exceptions.GeneralError
- `TestMalformedAttributes::test_wrong_size_aes_value`: pkcs11.exceptions.GeneralError
- `TestLargeAttributes::test_large_value`: pkcs11.exceptions.ObjectHandleInvalid

**test_blake2.py** (2 tests):
- `TestBlake2bProperties::test_empty_data`: pkcs11.exceptions.ArgumentsBad
- `TestBlake2bProperties::test_empty_data_blake2b_512`: pkcs11.exceptions.ArgumentsBad

**test_buffers.py** (1 tests):
- `TestDigestBufferSizes::test_empty_input`: pkcs11.exceptions.ArgumentsBad

**test_crossverify.py** (1 tests):
- `TestDigestCrossVerify::test_sha256_empty`: pkcs11.exceptions.ArgumentsBad

**test_digest.py** (2 tests):
- `TestDigestProperties::test_sha256_empty_data`: pkcs11.exceptions.ArgumentsBad
- `TestDigestProperties::test_sha1_empty_data`: pkcs11.exceptions.ArgumentsBad

**test_ecdh_extended.py** (3 tests):
- `TestECDH1CofactorDerive::test_cofactor_derive_shared_secret`: pkcs11.exceptions.MechanismParamInvalid
- `TestECDH1CofactorDerive::test_cofactor_matches_standard_ecdh`: pkcs11.exceptions.MechanismParamInvalid
- `TestECDH1CofactorDerive::test_cofactor_different_peers_different_secrets`: pkcs11.exceptions.MechanismParamInvalid

**test_errors.py** (1 tests):
- `TestEmptyInputs::test_digest_empty_data`: pkcs11.exceptions.ArgumentsBad

**test_fuzz.py** (3 tests):
- `TestDigestFuzz::test_sha256_deterministic`: hypothesis.errors.FlakyFailure: Inconsistent results from replaying a test case!   last: INTERESTING from ArgumentsBad at pkcs11/_pkcs11.pyx:53   this: INTERESTING from OperationActive at pkcs11/_pkcs
- `TestDigestFuzz::test_sha256_cross_verify`: hypothesis.errors.FlakyFailure: Inconsistent results from replaying a test case!   last: INTERESTING from ArgumentsBad at pkcs11/_pkcs11.pyx:53   this: INTERESTING from OperationActive at pkcs11/_pkcs
- `TestDigestFuzz::test_sha512_cross_verify`: hypothesis.errors.FlakyFailure: Inconsistent results from replaying a test case!   last: INTERESTING from ArgumentsBad at pkcs11/_pkcs11.pyx:53   this: INTERESTING from OperationActive at pkcs11/_pkcs

**test_gost.py** (1 tests):
- `TestGOSTR3411Digest::test_hmac_sign_verify`: pkcs11.exceptions.TemplateInconsistent

**test_hash_ml_dsa.py** (10 tests):
- `TestHashMLDSAVariants::test_empty_message[HASH_ML_DSA_SHA224]`: pkcs11.exceptions.GeneralError
- `TestHashMLDSAVariants::test_empty_message[HASH_ML_DSA_SHA256]`: pkcs11.exceptions.GeneralError
- `TestHashMLDSAVariants::test_empty_message[HASH_ML_DSA_SHA384]`: pkcs11.exceptions.GeneralError
- `TestHashMLDSAVariants::test_empty_message[HASH_ML_DSA_SHA512]`: pkcs11.exceptions.GeneralError
- `TestHashMLDSAVariants::test_empty_message[HASH_ML_DSA_SHA3_224]`: pkcs11.exceptions.GeneralError
- `TestHashMLDSAVariants::test_empty_message[HASH_ML_DSA_SHA3_256]`: pkcs11.exceptions.GeneralError
- `TestHashMLDSAVariants::test_empty_message[HASH_ML_DSA_SHA3_384]`: pkcs11.exceptions.GeneralError
- `TestHashMLDSAVariants::test_empty_message[HASH_ML_DSA_SHA3_512]`: pkcs11.exceptions.GeneralError
- `TestHashMLDSAVariants::test_empty_message[HASH_ML_DSA_SHAKE128]`: pkcs11.exceptions.GeneralError
- `TestHashMLDSAVariants::test_empty_message[HASH_ML_DSA_SHAKE256]`: pkcs11.exceptions.GeneralError

**test_hash_slh_dsa.py** (10 tests):
- `TestHashSLHDSAVariants::test_empty_message[HASH_SLH_DSA_SHA224]`: pkcs11.exceptions.GeneralError
- `TestHashSLHDSAVariants::test_empty_message[HASH_SLH_DSA_SHA256]`: pkcs11.exceptions.GeneralError
- `TestHashSLHDSAVariants::test_empty_message[HASH_SLH_DSA_SHA384]`: pkcs11.exceptions.GeneralError
- `TestHashSLHDSAVariants::test_empty_message[HASH_SLH_DSA_SHA512]`: pkcs11.exceptions.GeneralError
- `TestHashSLHDSAVariants::test_empty_message[HASH_SLH_DSA_SHA3_224]`: pkcs11.exceptions.GeneralError
- `TestHashSLHDSAVariants::test_empty_message[HASH_SLH_DSA_SHA3_256]`: pkcs11.exceptions.GeneralError
- `TestHashSLHDSAVariants::test_empty_message[HASH_SLH_DSA_SHA3_384]`: pkcs11.exceptions.GeneralError
- `TestHashSLHDSAVariants::test_empty_message[HASH_SLH_DSA_SHA3_512]`: pkcs11.exceptions.GeneralError
- `TestHashSLHDSAVariants::test_empty_message[HASH_SLH_DSA_SHAKE128]`: pkcs11.exceptions.GeneralError
- `TestHashSLHDSAVariants::test_empty_message[HASH_SLH_DSA_SHAKE256]`: pkcs11.exceptions.GeneralError

**test_hw_features.py** (5 tests):
- `TestHwFeatureEnumeration::test_hw_feature_type_readable`: NotImplementedError: Can't handle attribute type 0x300.
- `TestHwFeatureEnumeration::test_known_hw_feature_types`: NotImplementedError: Can't handle attribute type 0x300.
- `TestHwFeatureClock::test_clock_value_format`: NotImplementedError: Can't handle attribute type 0x300.
- `TestHwFeatureCounter::test_counter_has_value`: NotImplementedError: Can't handle attribute type 0x300.
- `TestHwFeatureCounter::test_counter_reset_attributes`: NotImplementedError: Can't handle attribute type 0x300.

**test_kat.py** (4 tests):
- `TestSHA256KAT::test_sha256_kat[e3b0c44298fc1c14]`: pkcs11.exceptions.ArgumentsBad
- `TestSHA512KAT::test_sha512_kat[cf83e1357eefb8bd]`: pkcs11.exceptions.ArgumentsBad
- `TestSHA1KAT::test_sha1_kat[da39a3ee5e6b4b0d]`: pkcs11.exceptions.ArgumentsBad
- `TestSHA384KAT::test_sha384_kat[38b060a751ac9638]`: pkcs11.exceptions.ArgumentsBad

**test_large_objects.py** (1 tests):
- `TestLargeDataObjects::test_1mb_data_object`: pkcs11.exceptions.ObjectHandleInvalid

**test_metamorphic.py** (1 tests):
- `TestDigestProperties::test_output_length_consistent`: pkcs11.exceptions.ArgumentsBad

**test_multipart_streaming.py** (1 tests):
- `TestMultipartDigest::test_sha256_large_data_crossverify[0]`: pkcs11.exceptions.ArgumentsBad

**test_salsa20.py** (7 tests):
- `TestSalsa20::test_salsa20_key_gen`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
- `TestSalsa20::test_salsa20_encrypt_decrypt`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
- `TestSalsa20::test_salsa20_different_nonces_differ`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
- `TestPoly1305::test_poly1305_key_gen`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
- `TestPoly1305::test_poly1305_sign_verify`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
- `TestPoly1305::test_poly1305_tamper_detection`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
- `TestPoly1305::test_poly1305_different_keys_differ`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.

**test_session_state_machine.py** (3 tests):
- `TestLoginConflicts::test_so_login_while_user_logged_in`: pkcs11.exceptions.PinIncorrect
- `TestLoginConflicts::test_user_login_via_second_session_rejected`: Failed: DID NOT RAISE any of (<class 'pkcs11.exceptions.UserAlreadyLoggedIn'>, <class 'pkcs11.exceptions.UserTypeInvalid'>)
- `TestROvsRWSessionState::test_so_login_requires_rw_session`: pkcs11.exceptions.PinIncorrect

**test_sha3.py** (4 tests):
- `TestSHA3Digest::test_sha3_empty[SHA3_256]`: pkcs11.exceptions.ArgumentsBad
- `TestSHA3Digest::test_sha3_empty[SHA3_384]`: pkcs11.exceptions.ArgumentsBad
- `TestSHA3Digest::test_sha3_empty[SHA3_512]`: pkcs11.exceptions.ArgumentsBad
- `TestSHA3Digest::test_sha3_empty[SHA3_224]`: pkcs11.exceptions.ArgumentsBad

**test_wycheproof.py** (7 tests):
- `TestHMACSHA256Wycheproof::test_hmac_sha256[tc1-valid]`: Failed: Valid HMAC vector tc1 failed: GeneralError
- `TestHMACSHA256Wycheproof::test_hmac_sha256[tc82-valid]`: Failed: Valid HMAC vector tc82 failed: GeneralError
- `TestHMACSHA256Wycheproof::test_hmac_sha256[tc163-valid]`: Failed: Valid HMAC vector tc163 failed: GeneralError
- `TestHMACSHA256Wycheproof::test_hmac_sha256[tc166-valid]`: Failed: Valid HMAC vector tc166 failed: GeneralError
- `TestHMACSHA256Wycheproof::test_hmac_sha256[tc169-valid]`: Failed: Valid HMAC vector tc169 failed: GeneralError
- `TestHMACSHA256Wycheproof::test_hmac_sha256[tc172-valid]`: Failed: Valid HMAC vector tc172 failed: GeneralError
- `TestRSASigWycheproof::test_rsa_sig_2048_sha256[tc1-valid]`: Failed: Valid RSA sig tc1 rejected

**test_wycheproof_mldsa_sign.py** (27 tests):
- `test_mldsa_sign[mldsa_44_sign_noseed_test.json:tc66-valid]`: Failed: Valid ML-DSA sign failed: mldsa_44_sign_noseed_test.json:tc66-valid
- `test_mldsa_sign[mldsa_44_sign_noseed_test.json:tc67-valid]`: Failed: Valid ML-DSA sign failed: mldsa_44_sign_noseed_test.json:tc67-valid
- `test_mldsa_sign[mldsa_44_sign_noseed_test.json:tc68-valid]`: Failed: Valid ML-DSA sign failed: mldsa_44_sign_noseed_test.json:tc68-valid
- `test_mldsa_sign[mldsa_44_sign_noseed_test.json:tc69-valid]`: Failed: Valid ML-DSA sign failed: mldsa_44_sign_noseed_test.json:tc69-valid
- `test_mldsa_sign[mldsa_44_sign_noseed_test.json:tc70-valid]`: Failed: Valid ML-DSA sign failed: mldsa_44_sign_noseed_test.json:tc70-valid
- `test_mldsa_sign[mldsa_44_sign_noseed_test.json:tc71-valid]`: Failed: Valid ML-DSA sign failed: mldsa_44_sign_noseed_test.json:tc71-valid
- `test_mldsa_sign[mldsa_44_sign_noseed_test.json:tc72-valid]`: Failed: Valid ML-DSA sign failed: mldsa_44_sign_noseed_test.json:tc72-valid
- `test_mldsa_sign[mldsa_65_sign_noseed_test.json:tc68-valid]`: Failed: Valid ML-DSA sign failed: mldsa_65_sign_noseed_test.json:tc68-valid
- `test_mldsa_sign[mldsa_65_sign_noseed_test.json:tc69-valid]`: Failed: Valid ML-DSA sign failed: mldsa_65_sign_noseed_test.json:tc69-valid
- `test_mldsa_sign[mldsa_65_sign_noseed_test.json:tc70-valid]`: Failed: Valid ML-DSA sign failed: mldsa_65_sign_noseed_test.json:tc70-valid
- ... and 17 more

**test_wycheproof_rsa_siggen.py** (10 tests):
- `test_rsa_pkcs1_siggen[rsa_pkcs1_2048_sig_gen_test.json:tc73]`: pkcs11.exceptions.GeneralError
- `test_rsa_pkcs1_siggen[rsa_pkcs1_2048_sig_gen_test.json:tc81]`: pkcs11.exceptions.GeneralError
- `test_rsa_pkcs1_siggen[rsa_pkcs1_2048_sig_gen_test.json:tc89]`: pkcs11.exceptions.GeneralError
- `test_rsa_pkcs1_siggen[rsa_pkcs1_2048_sig_gen_test.json:tc97]`: pkcs11.exceptions.GeneralError
- `test_rsa_pkcs1_siggen[rsa_pkcs1_3072_sig_gen_test.json:tc105]`: pkcs11.exceptions.GeneralError
- `test_rsa_pkcs1_siggen[rsa_pkcs1_3072_sig_gen_test.json:tc113]`: pkcs11.exceptions.GeneralError
- `test_rsa_pkcs1_siggen[rsa_pkcs1_3072_sig_gen_test.json:tc121]`: pkcs11.exceptions.GeneralError
- `test_rsa_pkcs1_siggen[rsa_pkcs1_4096_sig_gen_test.json:tc129]`: pkcs11.exceptions.GeneralError
- `test_rsa_pkcs1_siggen[rsa_pkcs1_4096_sig_gen_test.json:tc137]`: pkcs11.exceptions.GeneralError
- `test_rsa_pkcs1_siggen[rsa_pkcs1_4096_sig_gen_test.json:tc145]`: pkcs11.exceptions.GeneralError

**test_core_ops.py** (1 tests):
- `TestV30CertAttributes::test_v30_cert_attr_accepted[PUBLIC_KEY_INFO]`: Failed: v3.0+ module MUST accept CKA_PUBLIC_KEY_INFO but got AttributeValueInvalid

### kryoptic-fips (7 failures, 13 crashes)

Crashes covered in Priority 1.

**test_pbe.py** (7 tests):
- `TestPKCS5PBKD2::test_derive_generic_secret_sha256`: pkcs11.exceptions.DeviceError
- `TestPKCS5PBKD2::test_derive_generic_secret_sha1`: pkcs11.exceptions.DeviceError
- `TestPKCS5PBKD2::test_derive_deterministic`: pkcs11.exceptions.DeviceError
- `TestPKCS5PBKD2::test_different_password_different_key`: pkcs11.exceptions.DeviceError
- `TestPKCS5PBKD2::test_more_iterations_produces_different_key`: pkcs11.exceptions.DeviceError
- `TestPKCS5PBKD2::test_derive_aes_key`: pkcs11.exceptions.DeviceError
- `TestPKCS5PBKD2::test_string_password_accepted`: pkcs11.exceptions.DeviceError

### kryoptic-main (1 failures, 0 crashes)

**test_aes_kdf.py** (1 tests):
- `TestAESCBCEncryptData::test_derive_different_iv`: AssertionError: assert b'\xaa\x04\x8a\xc3\xb7\xc8\x14\xb9t\xbe\xce4\xc4\x1d\x88W' != b'\xaa\x04\x8a\xc3\xb7\xc8\x14\xb9t\xbe\xce4\xc4\x1d\x88W'

### nss-main (10 failures, 0 crashes)

**test_seed.py** (10 tests):
- `TestSEEDKeyGen::test_seed_key_gen`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
- `TestSEEDEncryption::test_seed_ecb_roundtrip`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
- `TestSEEDEncryption::test_seed_ecb_different_keys`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
- `TestSEEDEncryption::test_seed_cbc_roundtrip`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
- `TestSEEDEncryption::test_seed_cbc_different_ivs`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
- `TestSEEDEncryption::test_seed_cbc_pad_roundtrip`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
- `TestSEEDEncryption::test_seed_cbc_pad_different_keys`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
- `TestSEEDMAC::test_seed_mac_sign_verify`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
- `TestSEEDMAC::test_seed_mac_general_sign_verify`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.
- `TestSEEDMAC::test_seed_mac_different_keys`: pkcs11.exceptions.ArgumentsBad: No default capabilities for this key type. Please specify `capabilities`.

### opencryptoki (10 failures, 0 crashes)

**test_aes_modes.py** (1 tests):
- `TestAESKeyWrapPKCS7::test_aes_key_wrap_pkcs7_roundtrip`: pkcs11.exceptions.AttributeReadOnly

**test_attribute_enforcement.py** (1 tests):
- `TestCheckValue::test_imported_key_kcv_matches_ecb_encrypt`: AssertionError: KCV mismatch: got , expected 66e94b assert b'' == b'f\xe9K'      Use -v to get more diff

**test_cve_regression.py** (2 tests):
- `TestTookanUnwrapAttrs::test_unwrapped_key_preserves_extractable`: AssertionError: Tookan: unwrapped key is EXTRACTABLE despite template saying False assert True is False
- `TestECDSATimingBasic::test_ecdsa_timing_variance`: AssertionError: ECDSA timing CV=1.435 (mean=0.02ms, stdev=0.03ms) - possible timing leak assert 1.435035851908762 < 1.0

**test_des.py** (3 tests):
- `TestDESEncryption::test_des_ofb64_roundtrip`: pkcs11.exceptions.KeyTypeInconsistent
- `TestDESEncryption::test_des_cfb8_roundtrip`: pkcs11.exceptions.KeyTypeInconsistent
- `TestDESEncryption::test_des_cfb64_roundtrip`: pkcs11.exceptions.KeyTypeInconsistent

**test_dh_key_agreement.py** (1 tests):
- `TestDHKeyAgreement::test_dh_derived_key_encrypts`: pkcs11.exceptions.MechanismInvalid

**test_key_lifecycle.py** (2 tests):
- `TestAESKeyWrapLifecycle::test_aes_wrap_unwrap_roundtrip`: pkcs11.exceptions.AttributeReadOnly
- `TestAESKeyWrapLifecycle::test_aes_wrapped_key_functional`: pkcs11.exceptions.AttributeReadOnly

### softhsm2-main (0 failures, 4715 crashes)

Crashes covered in Priority 1 (4,715 wycheproof ECDH/ECDSA segfaults).

### tpm2 (727 failures, 0 crashes)

**test_ckr_codes.py** (5 tests):
- `TestCKRMechanismErrors::test_ckr_mechanism_invalid`: pkcs11.exceptions.FunctionNotSupported
- `TestCKRDataErrors::test_ckr_data_len_range_ecb`: pkcs11.exceptions.FunctionNotSupported
- `TestCKRAttributeErrors::test_ckr_attribute_sensitive`: pkcs11.exceptions.FunctionNotSupported
- `TestCKRAttributeErrors::test_ckr_attribute_type_invalid`: pkcs11.exceptions.FunctionNotSupported
- `TestCKRObjectErrors::test_ckr_object_handle_invalid_after_destroy`: pkcs11.exceptions.FunctionNotSupported

**test_ckr_decrypt.py** (13 tests):
- `TestDecryptInitErrors::test_mechanism_invalid`: pkcs11.exceptions.FunctionNotSupported
- `TestDecryptInitErrors::test_mechanism_param_invalid`: pkcs11.exceptions.FunctionNotSupported
- `TestDecryptDataErrors::test_ecb_ciphertext_not_aligned[1]`: pkcs11.exceptions.FunctionNotSupported
- `TestDecryptDataErrors::test_ecb_ciphertext_not_aligned[7]`: pkcs11.exceptions.FunctionNotSupported
- `TestDecryptDataErrors::test_ecb_ciphertext_not_aligned[15]`: pkcs11.exceptions.FunctionNotSupported
- `TestDecryptDataErrors::test_ecb_ciphertext_not_aligned[17]`: pkcs11.exceptions.FunctionNotSupported
- `TestDecryptDataErrors::test_ecb_ciphertext_not_aligned[31]`: pkcs11.exceptions.FunctionNotSupported
- `TestDecryptDataErrors::test_ecb_garbage_ciphertext`: pkcs11.exceptions.FunctionNotSupported
- `TestDecryptDataErrors::test_rsa_ciphertext_wrong_length`: pkcs11.exceptions.AttributeValueInvalid
- `TestDecryptDataErrors::test_cbc_pad_bad_padding`: pkcs11.exceptions.FunctionNotSupported
- ... and 3 more

**test_ckr_derive.py** (1 tests):
- `TestDeriveKeyErrors::test_mechanism_invalid`: pkcs11.exceptions.FunctionNotSupported

**test_ckr_dual.py** (3 tests):
- `TestOperationStateWrapper::test_encrypt_twice_succeeds`: pkcs11.exceptions.FunctionNotSupported
- `TestOperationStateWrapper::test_sign_then_encrypt`: pkcs11.exceptions.AttributeValueInvalid
- `TestOperationStateSubprocess::test_encrypt_without_init`: AssertionError: Subprocess crashed: WARNING:fapi:src/tss2-fapi/api/Fapi_List.c:228:Fapi_List_Finish() Profile of path not provisioned: /HS/SRK    ERROR:fapi:src/tss2-fapi/api/Fapi_List.c:81:Fapi_List(

**test_ckr_encrypt.py** (12 tests):
- `TestEncryptInitErrors::test_mechanism_invalid`: pkcs11.exceptions.FunctionNotSupported
- `TestEncryptInitErrors::test_key_function_not_permitted`: pkcs11.exceptions.FunctionNotSupported
- `TestEncryptInitErrors::test_mechanism_param_invalid`: pkcs11.exceptions.FunctionNotSupported
- `TestEncryptDataErrors::test_ecb_non_aligned[1]`: pkcs11.exceptions.FunctionNotSupported
- `TestEncryptDataErrors::test_ecb_non_aligned[7]`: pkcs11.exceptions.FunctionNotSupported
- `TestEncryptDataErrors::test_ecb_non_aligned[15]`: pkcs11.exceptions.FunctionNotSupported
- `TestEncryptDataErrors::test_ecb_non_aligned[17]`: pkcs11.exceptions.FunctionNotSupported
- `TestEncryptDataErrors::test_ecb_non_aligned[31]`: pkcs11.exceptions.FunctionNotSupported
- `TestEncryptDataErrors::test_ecb_non_aligned[33]`: pkcs11.exceptions.FunctionNotSupported
- `TestEncryptDataErrors::test_empty_data`: pkcs11.exceptions.FunctionNotSupported
- ... and 2 more

**test_ckr_keygen.py** (1 tests):
- `TestGenerateKeyErrors::test_template_inconsistent`: Failed: C_GenerateKey(conflicting_attributes): got FunctionNotSupported, not in acceptable set ['AttributeTypeInvalid', 'AttributeValueInvalid', 'TemplateIncomplete', 'TemplateInconsistent', 'Argument

**test_ckr_object.py** (4 tests):
- `TestGetAttributeErrors::test_sensitive_value`: pkcs11.exceptions.FunctionNotSupported
- `TestGetAttributeErrors::test_destroyed_handle`: pkcs11.exceptions.FunctionNotSupported
- `TestCopyObjectErrors::test_copy_destroyed_handle`: pkcs11.exceptions.FunctionNotSupported
- `TestDestroyObjectErrors::test_destroy_already_destroyed`: pkcs11.exceptions.FunctionNotSupported

**test_ckr_priority.py** (3 tests):
- `TestErrorPriority::test_destroyed_handle_with_wrong_mechanism`: pkcs11.exceptions.FunctionNotSupported
- `TestErrorPriority::test_wrong_key_type_with_nonaligned_data`: pkcs11.exceptions.AttributeValueInvalid
- `TestErrorPriority::test_bad_mechanism_with_bad_key_size`: pkcs11.exceptions.FunctionNotSupported

**test_ckr_raw_args_bad.py** (1 tests):
- `TestArgsBadNullPointers::test_generate_key_null_mechanism`: AssertionError: C_GenerateKey(NULL mech) subprocess error: s11/blob/1.9.1/docs/FAPI.md for more details   WARNING: Getting tokens from fapi backend failed.   Traceback (most recent call last):     Fil

**test_ckr_raw_buffer.py** (1 tests):
- `TestBufferTooSmall::test_encrypt_buffer_too_small`: AssertionError: Crash: iled: "fapi:Provisioning was not executed."   Please see https://github.com/tpm2-software/tpm2-pkcs11/blob/1.9.1/docs/FAPI.md for more details   WARNING: Getting tokens from fap

**test_ckr_raw_state.py** (5 tests):
- `TestOperationActive::test_double_encrypt_init`: AssertionError: Crash: Provisioning was not executed."   Please see https://github.com/tpm2-software/tpm2-pkcs11/blob/1.9.1/docs/FAPI.md for more details   WARNING: Getting tokens from fapi backend fa
- `TestOperationActive::test_encrypt_then_sign_init`: AssertionError: Crash: Provisioning was not executed."   Please see https://github.com/tpm2-software/tpm2-pkcs11/blob/1.9.1/docs/FAPI.md for more details   WARNING: Getting tokens from fapi backend fa
- `TestOperationActive::test_double_digest_init`: AssertionError: Crash: Provisioning was not executed."   Please see https://github.com/tpm2-software/tpm2-pkcs11/blob/1.9.1/docs/FAPI.md for more details   WARNING: Getting tokens from fapi backend fa
- `TestOperationActive::test_double_sign_init`: AssertionError: Crash: Provisioning was not executed."   Please see https://github.com/tpm2-software/tpm2-pkcs11/blob/1.9.1/docs/FAPI.md for more details   WARNING: Getting tokens from fapi backend fa
- `TestOperationActive::test_double_decrypt_init`: AssertionError: Crash: Provisioning was not executed."   Please see https://github.com/tpm2-software/tpm2-pkcs11/blob/1.9.1/docs/FAPI.md for more details   WARNING: Getting tokens from fapi backend fa

**test_ckr_sign.py** (4 tests):
- `TestSignInitErrors::test_mechanism_invalid`: pkcs11.exceptions.AttributeValueInvalid
- `TestSignInitErrors::test_mechanism_param_invalid`: pkcs11.exceptions.AttributeValueInvalid
- `TestSignInitErrors::test_key_handle_invalid`: pkcs11.exceptions.AttributeValueInvalid
- `TestSignDataErrors::test_rsa_pkcs_data_too_long`: pkcs11.exceptions.AttributeValueInvalid

**test_ckr_spec_compliance.py** (6 tests):
- `TestCKRMechanismCompliance::test_sha256_as_encrypt_returns_mechanism_invalid`: pkcs11.exceptions.FunctionNotSupported
- `TestCKRMechanismCompliance::test_non_aligned_ecb_returns_data_len_range`: pkcs11.exceptions.FunctionNotSupported
- `TestCKRAttributeCompliance::test_sensitive_value_returns_attribute_sensitive`: pkcs11.exceptions.FunctionNotSupported
- `TestCKRObjectCompliance::test_destroyed_handle_returns_object_handle_invalid`: pkcs11.exceptions.FunctionNotSupported
- `TestCKRVerifyCompliance::test_bad_signature_returns_signature_invalid`: pkcs11.exceptions.AttributeValueInvalid
- `TestCKRMultipartCompliance::test_aes_cbc_multipart_roundtrip`: pkcs11.exceptions.FunctionNotSupported

**test_ckr_verify.py** (4 tests):
- `TestVerifyInitErrors::test_mechanism_invalid`: pkcs11.exceptions.AttributeValueInvalid
- `TestVerifyInitErrors::test_key_handle_invalid`: pkcs11.exceptions.AttributeValueInvalid
- `TestVerifyErrors::test_signature_invalid`: pkcs11.exceptions.AttributeValueInvalid
- `TestVerifyErrors::test_signature_wrong_length`: pkcs11.exceptions.AttributeValueInvalid

**test_ckr_wrap.py** (1 tests):
- `TestWrapKeyErrors::test_mechanism_invalid`: pkcs11.exceptions.FunctionNotSupported

**test_access.py** (4 tests):
- `TestSessionTypes::test_rw_session_can_generate_key`: pkcs11.exceptions.FunctionNotSupported
- `TestLoginStates::test_user_session_can_see_private`: pkcs11.exceptions.AttributeValueInvalid
- `TestMultipleSessions::test_two_sessions_independent`: pkcs11.exceptions.FunctionNotSupported
- `TestSessionLifecycle::test_session_object_destroyed_on_close`: pkcs11.exceptions.FunctionNotSupported

**test_access_control.py** (3 tests):
- `TestPrivateAttribute::test_private_key_default_is_private`: pkcs11.exceptions.FunctionNotSupported
- `TestModifiableAttribute::test_default_key_is_modifiable`: pkcs11.exceptions.FunctionNotSupported
- `TestModifiableAttribute::test_modifiable_key_label_changeable`: pkcs11.exceptions.FunctionNotSupported

**test_access_levels.py** (12 tests):
- `TestPublicSessionVisibility::test_public_sees_non_private_objects`: pkcs11.exceptions.AttributeValueInvalid
- `TestPublicSessionVisibility::test_public_cannot_see_private_objects`: pkcs11.exceptions.FunctionNotSupported
- `TestPublicSessionVisibility::test_public_session_can_digest`: pkcs11.exceptions.UserNotLoggedIn
- `TestUserSessionCapabilities::test_user_sees_private_objects`: pkcs11.exceptions.FunctionNotSupported
- `TestUserSessionCapabilities::test_user_sees_non_private_objects`: pkcs11.exceptions.AttributeValueInvalid
- `TestUserSessionCapabilities::test_user_can_create_and_destroy_objects`: pkcs11.exceptions.FunctionNotSupported
- `TestUserSessionCapabilities::test_user_can_encrypt_decrypt`: pkcs11.exceptions.FunctionNotSupported
- `TestAccessLevelMatrix::test_session_public_object_visible_in_public`: pkcs11.exceptions.AttributeValueInvalid
- `TestAccessLevelMatrix::test_token_public_object_visible_in_public`: pkcs11.exceptions.AttributeValueInvalid
- `TestAccessLevelMatrix::test_token_private_object_invisible_in_public`: pkcs11.exceptions.FunctionNotSupported
- ... and 2 more

**test_aead.py** (1 tests):
- `TestAESGCMCrossVerify::test_gcm_decrypt_crossverify`: pkcs11.exceptions.GeneralError

**test_aes_modes.py** (2 tests):
- `TestAESCFB::test_aes_cfb_roundtrip[CFB128]`: pkcs11.exceptions.FunctionNotSupported
- `TestAESCFB::test_aes_cfb_different_keys[CFB128]`: pkcs11.exceptions.FunctionNotSupported

**test_api_security.py** (10 tests):
- `TestSensitiveExtraction::test_sensitive_key_value_not_readable`: pkcs11.exceptions.FunctionNotSupported
- `TestSensitiveExtraction::test_private_key_not_extractable`: pkcs11.exceptions.AttributeValueInvalid
- `TestAttributeEscalation::test_extractable_cannot_be_set_true`: pkcs11.exceptions.FunctionNotSupported
- `TestAttributeEscalation::test_sensitive_cannot_be_set_false`: pkcs11.exceptions.FunctionNotSupported
- `TestAttributeLaunderingViaCopy::test_copy_cannot_escalate_extractable`: pkcs11.exceptions.FunctionNotSupported
- `TestAttributeLaunderingViaCopy::test_copy_cannot_downgrade_sensitive`: pkcs11.exceptions.FunctionNotSupported
- `TestKeyUsageRestrictions::test_encrypt_disabled_removes_capability`: pkcs11.exceptions.FunctionNotSupported
- `TestKeyUsageRestrictions::test_non_extractable_enforced`: pkcs11.exceptions.FunctionNotSupported
- `TestKeyUsageRestrictions::test_decrypt_only_key`: pkcs11.exceptions.FunctionNotSupported
- `TestAccessControl::test_handle_prediction`: pkcs11.exceptions.FunctionNotSupported

**test_attribute_defaults.py** (1 tests):
- `TestSecretKeyDefaults::test_token_is_false`: pkcs11.exceptions.FunctionNotSupported

**test_attribute_enforcement.py** (8 tests):
- `TestCopyableOneWay::test_copyable_false_cannot_be_set_true`: pkcs11.exceptions.FunctionNotSupported
- `TestCopyableOneWay::test_copyable_true_can_be_set_false`: pkcs11.exceptions.FunctionNotSupported
- `TestDestroyable::test_destroyable_readable`: pkcs11.exceptions.FunctionNotSupported
- `TestDestroyable::test_destroyable_true_allows_destroy`: pkcs11.exceptions.FunctionNotSupported
- `TestKeyGenMechanism::test_generated_aes_key_has_aes_key_gen`: pkcs11.exceptions.FunctionNotSupported
- `TestKeyGenMechanism::test_generated_rsa_keypair_has_rsa_gen`: pkcs11.exceptions.AttributeValueInvalid
- `TestAlwaysAuthenticate::test_always_authenticate_readable`: pkcs11.exceptions.AttributeValueInvalid
- `TestDateAttributes::test_empty_dates_by_default`: pkcs11.exceptions.FunctionNotSupported

**test_attribute_fuzz.py** (1 tests):
- `TestDuplicateAttributes::test_create_key_normal`: pkcs11.exceptions.FunctionNotSupported

**test_authenticated_wrap.py** (1 tests):
- `TestAuthenticatedWrap::test_authenticated_wrap_requires_v32`: pkcs11.exceptions.FunctionNotSupported

**test_benchmark.py** (4 tests):
- `test_bench_aes256_cbc_encrypt`: pkcs11.exceptions.FunctionNotSupported
- `test_bench_aes256_ecb_encrypt`: pkcs11.exceptions.FunctionNotSupported
- `test_bench_aes_keygen`: pkcs11.exceptions.FunctionNotSupported
- `test_bench_rsa2048_sign`: pkcs11.exceptions.AttributeValueInvalid

**test_buffers.py** (6 tests):
- `TestEncryptBufferSizes::test_single_block`: pkcs11.exceptions.FunctionNotSupported
- `TestEncryptBufferSizes::test_two_blocks`: pkcs11.exceptions.FunctionNotSupported
- `TestEncryptBufferSizes::test_100_blocks`: pkcs11.exceptions.FunctionNotSupported
- `TestEncryptBufferSizes::test_64kb`: pkcs11.exceptions.FunctionNotSupported
- `TestSignBufferSizes::test_sign_single_byte`: pkcs11.exceptions.AttributeValueInvalid
- `TestSignBufferSizes::test_sign_100kb`: pkcs11.exceptions.AttributeValueInvalid

**test_crossverify.py** (14 tests):
- `TestAESCrossVerify::test_aes_256_ecb_encrypt`: pkcs11.exceptions.GeneralError
- `TestAESCrossVerify::test_aes_128_ecb_encrypt`: pkcs11.exceptions.GeneralError
- `TestAESCrossVerify::test_aes_ecb_decrypt`: pkcs11.exceptions.GeneralError
- `TestAESCrossVerify::test_aes_ecb_multiblock`: pkcs11.exceptions.GeneralError
- `TestRSACrossVerify::test_rsa_pkcs_sign`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSACrossVerify::test_rsa_4096_sign`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSACrossVerify::test_rsa_sha512_sign`: pkcs11.exceptions.AttributeValueInvalid
- `TestECDSACrossVerify::test_ecdsa_p256`: pkcs11.exceptions.AttributeValueInvalid
- `TestECDSACrossVerify::test_ecdsa_p384`: pkcs11.exceptions.AttributeValueInvalid
- `TestDigestCrossVerify::test_sha224`: pkcs11.exceptions.MechanismInvalid
- ... and 4 more

**test_crossverify_extended.py** (4 tests):
- `TestAESCBCCrossVerify::test_aes_cbc_encrypt_crossverify`: pkcs11.exceptions.GeneralError
- `TestAESCBCCrossVerify::test_aes_cbc_decrypt_crossverify`: pkcs11.exceptions.GeneralError
- `TestRSAPSSCrossVerify::test_rsa_pss_sign_p11_verify_crypto`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAOAEPCrossVerify::test_rsa_oaep_encrypt_p11_decrypt_crypto`: pkcs11.exceptions.AttributeValueInvalid

**test_cve_regression.py** (5 tests):
- `TestCKADeriveOnEC::test_ec_keygen_with_derive`: pkcs11.exceptions.AttributeValueInvalid
- `TestSessionObjectsAfterLogout::test_session_objects_after_logout`: pkcs11.exceptions.FunctionNotSupported
- `TestROCAFingerprint::test_rsa_modulus_not_roca`: pkcs11.exceptions.AttributeValueInvalid
- `TestBoundaryLengthCrypto::test_rsa_encrypt_boundary`: pkcs11.exceptions.AttributeValueInvalid
- `TestTPM2Issue44::test_rapid_sign_no_deadlock`: pkcs11.exceptions.AttributeValueInvalid

**test_data_objects.py** (1 tests):
- `TestDataObjectCreate::test_create_data_object_empty_value`: pkcs11.exceptions.AttributeValueInvalid

**test_digest.py** (5 tests):
- `TestDigestLengths::test_digest_length[SHA-224]`: pkcs11.exceptions.MechanismInvalid
- `TestDigestCrossVerify::test_cross_verify[SHA-224]`: pkcs11.exceptions.MechanismInvalid
- `TestDigestKey::test_digest_key_matches_hashlib`: pkcs11.exceptions.FunctionNotSupported
- `TestDigestKey::test_digest_key_with_data`: pkcs11.exceptions.FunctionNotSupported
- `TestDigestKey::test_digest_key_256bit`: pkcs11.exceptions.FunctionNotSupported

**test_duplicate_labels.py** (3 tests):
- `TestDuplicateLabels::test_two_keys_same_label`: pkcs11.exceptions.FunctionNotSupported
- `TestDuplicateLabels::test_different_types_same_label`: pkcs11.exceptions.FunctionNotSupported
- `TestDuplicateLabels::test_destroy_one_of_duplicates`: pkcs11.exceptions.FunctionNotSupported

**test_encrypt.py** (13 tests):
- `TestAESEncryption::test_aes_generate_key`: pkcs11.exceptions.FunctionNotSupported
- `TestAESEncryption::test_aes_cbc_roundtrip`: pkcs11.exceptions.FunctionNotSupported
- `TestAESEncryption::test_aes_different_keys_different_ciphertext`: pkcs11.exceptions.FunctionNotSupported
- `TestAESEncryption::test_aes_ecb_roundtrip`: pkcs11.exceptions.FunctionNotSupported
- `TestAESEncryption::test_aes_key_sizes[128]`: pkcs11.exceptions.FunctionNotSupported
- `TestAESEncryption::test_aes_key_sizes[192]`: pkcs11.exceptions.FunctionNotSupported
- `TestAESEncryption::test_aes_key_sizes[256]`: pkcs11.exceptions.FunctionNotSupported
- `TestAESEncryption::test_aes_ciphertext_length`: pkcs11.exceptions.FunctionNotSupported
- `TestAESEncryption::test_aes_encrypt_not_deterministic_cbc`: pkcs11.exceptions.FunctionNotSupported
- `TestAESEncryption::test_aes_wrong_key_decrypt_fails`: pkcs11.exceptions.FunctionNotSupported
- ... and 3 more

**test_errors.py** (12 tests):
- `TestInvalidOperations::test_invalid_mechanism_param`: pkcs11.exceptions.FunctionNotSupported
- `TestInvalidOperations::test_verify_with_wrong_mechanism`: pkcs11.exceptions.AttributeValueInvalid
- `TestInvalidOperations::test_encrypt_with_sign_key`: pkcs11.exceptions.AttributeValueInvalid
- `TestInvalidOperations::test_decrypt_garbage`: pkcs11.exceptions.AttributeValueInvalid
- `TestEmptyInputs::test_encrypt_empty_data`: pkcs11.exceptions.FunctionNotSupported
- `TestEmptyInputs::test_sign_empty_data`: pkcs11.exceptions.AttributeValueInvalid
- `TestKeyLifecycle::test_use_destroyed_key`: pkcs11.exceptions.FunctionNotSupported
- `TestKeyLifecycle::test_bulk_key_generation`: pkcs11.exceptions.FunctionNotSupported
- `TestKeyLifecycle::test_key_attribute_access`: pkcs11.exceptions.FunctionNotSupported
- `TestSessionEdgeCases::test_sign_verify_large_data`: pkcs11.exceptions.AttributeValueInvalid
- ... and 2 more

**test_fuzz.py** (6 tests):
- `TestAESFuzz::test_ecb_roundtrip`: pkcs11.exceptions.FunctionNotSupported Falsifying example: test_ecb_roundtrip(     self=<pkcs11_check.testcases.test_fuzz.TestAESFuzz object at 0x7d6460ffeb40>,     p11_session=<pkcs11._pkcs11.Session
- `TestAESFuzz::test_ecb_deterministic`: pkcs11.exceptions.FunctionNotSupported Falsifying example: test_ecb_deterministic(     self=<pkcs11_check.testcases.test_fuzz.TestAESFuzz object at 0x7d6460a42060>,     p11_session=<pkcs11._pkcs11.Ses
- `TestAESFuzz::test_ecb_ciphertext_differs_from_plaintext`: pkcs11.exceptions.FunctionNotSupported Falsifying example: test_ecb_ciphertext_differs_from_plaintext(     self=<pkcs11_check.testcases.test_fuzz.TestAESFuzz object at 0x7d6460a41760>,     p11_session
- `TestRSAFuzz::test_sign_verify_roundtrip`: pkcs11.exceptions.AttributeValueInvalid Falsifying example: test_sign_verify_roundtrip(     self=<pkcs11_check.testcases.test_fuzz.TestRSAFuzz object at 0x7d6460a42ab0>,     p11_session=<pkcs11._pkcs1
- `TestRSAFuzz::test_signature_length_constant`: pkcs11.exceptions.AttributeValueInvalid Falsifying example: test_signature_length_constant(     self=<pkcs11_check.testcases.test_fuzz.TestRSAFuzz object at 0x7d6460a42de0>,     p11_session=<pkcs11._p
- `TestECDSAFuzz::test_ecdsa_sign_verify_roundtrip`: pkcs11.exceptions.AttributeValueInvalid Falsifying example: test_ecdsa_sign_verify_roundtrip(     self=<pkcs11_check.testcases.test_fuzz.TestECDSAFuzz object at 0x7d6460a43830>,     p11_session=<pkcs1

**test_generic_secret.py** (2 tests):
- `TestGenericSecretHMAC::test_hmac_with_imported_generic_secret`: pkcs11.exceptions.GeneralError
- `TestGenericSecretHMAC::test_hmac_sha512_crossverify`: pkcs11.exceptions.GeneralError

**test_handle_reuse.py** (7 tests):
- `TestHandleReuseAfterDestroy::test_get_attribute_after_destroy`: pkcs11.exceptions.FunctionNotSupported
- `TestHandleReuseAfterDestroy::test_encrypt_after_destroy`: pkcs11.exceptions.FunctionNotSupported
- `TestHandleReuseAfterDestroy::test_sign_after_destroy`: pkcs11.exceptions.AttributeValueInvalid
- `TestHandleReuseAfterDestroy::test_wrap_after_destroy`: pkcs11.exceptions.FunctionNotSupported
- `TestHandleReuseAfterDestroy::test_double_destroy`: pkcs11.exceptions.FunctionNotSupported
- `TestHandleReuseAfterDestroy::test_set_attribute_after_destroy`: pkcs11.exceptions.FunctionNotSupported
- `TestHandleReuseAfterDestroy::test_copy_after_destroy`: pkcs11.exceptions.FunctionNotSupported

**test_interop.py** (13 tests):
- `TestRSAInterop::test_sign_in_p11_verify_in_crypto`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAInterop::test_rsa_pubkey_pem_roundtrip`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAInterop::test_rsa_pss_sign_p11_verify_crypto`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAInterop::test_rsa_multi_hash_interop[SHA256]`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAInterop::test_rsa_multi_hash_interop[SHA384]`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAInterop::test_rsa_multi_hash_interop[SHA512]`: pkcs11.exceptions.AttributeValueInvalid
- `TestECDSAInterop::test_ecdsa_sign_p11_verify_crypto`: pkcs11.exceptions.AttributeValueInvalid
- `TestECDSAInterop::test_ecdsa_multi_curve_interop[P-256]`: pkcs11.exceptions.AttributeValueInvalid
- `TestECDSAInterop::test_ecdsa_multi_curve_interop[P-384]`: pkcs11.exceptions.AttributeValueInvalid
- `TestAESInterop::test_aes_ecb_encrypt_p11_decrypt_crypto`: pkcs11.exceptions.GeneralError
- ... and 3 more

**test_kat.py** (9 tests):
- `TestSHA224KAT::test_sha224_kat[23097d223405d822]`: pkcs11.exceptions.MechanismInvalid
- `TestAESECBKAT::test_aes_ecb_encrypt_kat[f3eed1bdb5d2a03c]`: pkcs11.exceptions.GeneralError
- `TestAESECBKAT::test_aes_ecb_encrypt_kat[591ccb10d410ed26]`: pkcs11.exceptions.GeneralError
- `TestAESECBKAT::test_aes_ecb_encrypt_kat[b6ed21b99ca6f4f9]`: pkcs11.exceptions.GeneralError
- `TestAESECBKAT::test_aes_ecb_encrypt_kat[23304b7a39f9f3ff]`: pkcs11.exceptions.GeneralError
- `TestAESECBKAT::test_aes_ecb_decrypt_kat[6bc1bee22e409f96]`: pkcs11.exceptions.GeneralError
- `TestAESECBKAT::test_aes_ecb_decrypt_kat[ae2d8a571e03ac9c]`: pkcs11.exceptions.GeneralError
- `TestAESECBKAT::test_aes_ecb_decrypt_kat[30c81c46a35ce411]`: pkcs11.exceptions.GeneralError
- `TestAESECBKAT::test_aes_ecb_decrypt_kat[f69f2445df4f9b17]`: pkcs11.exceptions.GeneralError

**test_kdf.py** (3 tests):
- `TestKeyDeriveSoftware::test_hmac_as_kdf`: pkcs11.exceptions.GeneralError
- `TestKeyDeriveSoftware::test_hmac_sha512_as_kdf`: pkcs11.exceptions.GeneralError
- `TestECDHDerive::test_ecdh_keypair_independence`: pkcs11.exceptions.AttributeValueInvalid

**test_key_flags.py** (13 tests):
- `TestNeverExtractable::test_generated_non_extractable_is_never_extractable`: pkcs11.exceptions.FunctionNotSupported
- `TestNeverExtractable::test_generated_extractable_is_not_never_extractable`: pkcs11.exceptions.FunctionNotSupported
- `TestLocalFlag::test_imported_key_is_not_local`: pkcs11.exceptions.AttributeTypeInvalid
- `TestAlwaysSensitive::test_sensitive_key_always_sensitive`: pkcs11.exceptions.FunctionNotSupported
- `TestAlwaysSensitive::test_non_sensitive_key_not_always_sensitive`: pkcs11.exceptions.FunctionNotSupported
- `TestAutopadding::test_aes_cbc_pad_variable_length[1]`: pkcs11.exceptions.FunctionNotSupported
- `TestAutopadding::test_aes_cbc_pad_variable_length[7]`: pkcs11.exceptions.FunctionNotSupported
- `TestAutopadding::test_aes_cbc_pad_variable_length[15]`: pkcs11.exceptions.FunctionNotSupported
- `TestAutopadding::test_aes_cbc_pad_variable_length[16]`: pkcs11.exceptions.FunctionNotSupported
- `TestAutopadding::test_aes_cbc_pad_variable_length[17]`: pkcs11.exceptions.FunctionNotSupported
- ... and 3 more

**test_key_lifecycle.py** (3 tests):
- `TestRSAKeyLifecycle::test_rsa_export_import_verify`: pkcs11.exceptions.AttributeValueInvalid
- `TestKeyDestroyVerification::test_destroyed_key_not_findable`: pkcs11.exceptions.FunctionNotSupported
- `TestKeyDestroyVerification::test_destroy_does_not_affect_other_keys`: pkcs11.exceptions.FunctionNotSupported

**test_key_sizes.py** (14 tests):
- `TestAESKeySizes::test_aes_generate[128]`: pkcs11.exceptions.FunctionNotSupported
- `TestAESKeySizes::test_aes_generate[192]`: pkcs11.exceptions.FunctionNotSupported
- `TestAESKeySizes::test_aes_generate[256]`: pkcs11.exceptions.FunctionNotSupported
- `TestAESKeySizes::test_aes_ecb_roundtrip[128]`: pkcs11.exceptions.FunctionNotSupported
- `TestAESKeySizes::test_aes_ecb_roundtrip[192]`: pkcs11.exceptions.FunctionNotSupported
- `TestAESKeySizes::test_aes_ecb_roundtrip[256]`: pkcs11.exceptions.FunctionNotSupported
- `TestRSAKeySizes::test_rsa_generate[2048]`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAKeySizes::test_rsa_generate[3072]`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAKeySizes::test_rsa_generate[4096]`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAKeySizes::test_rsa_sign_verify[2048]`: pkcs11.exceptions.AttributeValueInvalid
- ... and 4 more

**test_key_usage_policy.py** (8 tests):
- `TestAESKeyUsagePolicy::test_encrypt_only_key_has_no_decrypt`: pkcs11.exceptions.FunctionNotSupported
- `TestAESKeyUsagePolicy::test_decrypt_only_key_has_no_encrypt`: pkcs11.exceptions.FunctionNotSupported
- `TestAESKeyUsagePolicy::test_sign_only_key_has_no_encrypt`: pkcs11.exceptions.FunctionNotSupported
- `TestAESKeyUsagePolicy::test_full_capabilities_key_has_all_methods`: pkcs11.exceptions.FunctionNotSupported
- `TestRSAKeyUsagePolicy::test_sign_only_rsa_has_no_encrypt`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAKeyUsagePolicy::test_encrypt_only_rsa_has_no_sign`: pkcs11.exceptions.AttributeValueInvalid
- `TestCapabilityReadback::test_aes_capabilities_match_template`: pkcs11.exceptions.FunctionNotSupported
- `TestCapabilityReadback::test_rsa_capabilities_match_template`: pkcs11.exceptions.AttributeValueInvalid

**test_keymgmt.py** (6 tests):
- `TestKeyImport::test_import_aes_key_roundtrip`: pkcs11.exceptions.GeneralError
- `TestKeyExport::test_rsa_modulus_export`: pkcs11.exceptions.AttributeValueInvalid
- `TestKeyExport::test_ec_point_export`: pkcs11.exceptions.AttributeValueInvalid
- `TestKeyCopy::test_copy_preserves_attributes`: pkcs11.exceptions.FunctionNotSupported
- `TestKeyCopy::test_copy_independent`: pkcs11.exceptions.FunctionNotSupported
- `TestKeyDerive::test_ecdh_derive_produces_key`: pkcs11.exceptions.AttributeValueInvalid

**test_keypair_consistency.py** (3 tests):
- `TestRSAKeypairConsistency::test_modulus_matches`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAKeypairConsistency::test_public_exponent_matches`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAKeypairConsistency::test_modulus_correct_size`: pkcs11.exceptions.AttributeValueInvalid

**test_large_objects.py** (1 tests):
- `TestLargeEncryption::test_encrypt_64kb_aes_ecb`: pkcs11.exceptions.FunctionNotSupported

**test_mechanism_fuzz.py** (9 tests):
- `TestAESParameterFuzz::test_aes_cbc_bad_iv[empty]`: pkcs11.exceptions.FunctionNotSupported
- `TestAESParameterFuzz::test_aes_cbc_bad_iv[one-byte]`: pkcs11.exceptions.FunctionNotSupported
- `TestAESParameterFuzz::test_aes_cbc_bad_iv[8-bytes]`: pkcs11.exceptions.FunctionNotSupported
- `TestAESParameterFuzz::test_aes_cbc_bad_iv[15-bytes]`: pkcs11.exceptions.FunctionNotSupported
- `TestAESParameterFuzz::test_aes_cbc_bad_iv[random-7]`: pkcs11.exceptions.FunctionNotSupported
- `TestAESParameterFuzz::test_aes_ecb_with_param_should_fail_or_ignore`: pkcs11.exceptions.FunctionNotSupported
- `TestSignParameterFuzz::test_rsa_pkcs_sign_with_random_param`: pkcs11.exceptions.AttributeValueInvalid
- `TestEncryptDataFuzz::test_encrypt_empty_data`: pkcs11.exceptions.FunctionNotSupported
- `TestEncryptDataFuzz::test_encrypt_non_block_aligned`: pkcs11.exceptions.FunctionNotSupported

**test_metamorphic.py** (10 tests):
- `TestRoundTripInvariants::test_aes_ecb_roundtrip[128]`: pkcs11.exceptions.FunctionNotSupported
- `TestRoundTripInvariants::test_aes_ecb_roundtrip[192]`: pkcs11.exceptions.FunctionNotSupported
- `TestRoundTripInvariants::test_aes_ecb_roundtrip[256]`: pkcs11.exceptions.FunctionNotSupported
- `TestRoundTripInvariants::test_aes_cbc_roundtrip`: pkcs11.exceptions.FunctionNotSupported
- `TestRoundTripInvariants::test_rsa_sign_verify_roundtrip`: pkcs11.exceptions.AttributeValueInvalid
- `TestRoundTripInvariants::test_rsa_wrong_data_verify_fails`: pkcs11.exceptions.AttributeValueInvalid
- `TestDeterminismInvariants::test_ecb_deterministic`: pkcs11.exceptions.FunctionNotSupported
- `TestDeterminismInvariants::test_different_keys_different_ciphertext`: pkcs11.exceptions.FunctionNotSupported
- `TestCopyEquivalence::test_copy_produces_same_ciphertext`: pkcs11.exceptions.FunctionNotSupported
- `TestCopyEquivalence::test_copy_can_decrypt_original`: pkcs11.exceptions.FunctionNotSupported

**test_multipart.py** (5 tests):
- `TestMultiPartEncrypt::test_encrypt_16kb`: pkcs11.exceptions.FunctionNotSupported
- `TestMultiPartEncrypt::test_encrypt_various_block_sizes`: pkcs11.exceptions.FunctionNotSupported
- `TestMultiPartEncrypt::test_encrypt_same_key_deterministic`: pkcs11.exceptions.FunctionNotSupported
- `TestMultiPartSign::test_rsa_sign_10kb`: pkcs11.exceptions.AttributeValueInvalid
- `TestMultiPartSign::test_rsa_sign_1byte`: pkcs11.exceptions.AttributeValueInvalid

**test_multipart_streaming.py** (13 tests):
- `TestMultipartEncrypt::test_aes_ecb_multiblock_roundtrip[1]`: pkcs11.exceptions.FunctionNotSupported
- `TestMultipartEncrypt::test_aes_ecb_multiblock_roundtrip[4]`: pkcs11.exceptions.FunctionNotSupported
- `TestMultipartEncrypt::test_aes_ecb_multiblock_roundtrip[16]`: pkcs11.exceptions.FunctionNotSupported
- `TestMultipartEncrypt::test_aes_ecb_multiblock_roundtrip[64]`: pkcs11.exceptions.FunctionNotSupported
- `TestMultipartEncrypt::test_aes_ecb_multiblock_roundtrip[256]`: pkcs11.exceptions.FunctionNotSupported
- `TestMultipartEncrypt::test_aes_ecb_multiblock_roundtrip[1024]`: pkcs11.exceptions.FunctionNotSupported
- `TestMultipartEncrypt::test_aes_ecb_crossverify_large[16]`: pkcs11.exceptions.GeneralError
- `TestMultipartEncrypt::test_aes_ecb_crossverify_large[256]`: pkcs11.exceptions.GeneralError
- `TestMultipartEncrypt::test_aes_ecb_crossverify_large[4096]`: pkcs11.exceptions.GeneralError
- `TestMultipartEncrypt::test_aes_ecb_crossverify_large[65536]`: pkcs11.exceptions.GeneralError
- ... and 3 more

**test_nonce_quality.py** (4 tests):
- `TestECDSANonceReuse::test_nonce_reuse_p256`: pkcs11.exceptions.AttributeValueInvalid
- `TestECDSANonceReuse::test_different_messages_different_r`: pkcs11.exceptions.AttributeValueInvalid
- `TestECDSADeterminism::test_deterministic_check`: pkcs11.exceptions.AttributeValueInvalid
- `TestECDSANonceBias::test_r_value_distribution`: pkcs11.exceptions.AttributeValueInvalid

**test_object.py** (13 tests):
- `TestSessionObjects::test_create_secret_key_with_label`: pkcs11.exceptions.FunctionNotSupported
- `TestSessionObjects::test_find_objects_by_label`: pkcs11.exceptions.FunctionNotSupported
- `TestSessionObjects::test_key_attributes_readable`: pkcs11.exceptions.FunctionNotSupported
- `TestSessionObjects::test_destroy_session_object`: pkcs11.exceptions.FunctionNotSupported
- `TestSessionObjects::test_multiple_keys_same_type`: pkcs11.exceptions.FunctionNotSupported
- `TestSessionObjects::test_find_by_object_class`: pkcs11.exceptions.FunctionNotSupported
- `TestKeyPairAttributes::test_rsa_keypair_attributes`: pkcs11.exceptions.AttributeValueInvalid
- `TestKeyPairAttributes::test_rsa_modulus_readable`: pkcs11.exceptions.AttributeValueInvalid
- `TestKeyPairAttributes::test_rsa_public_exponent`: pkcs11.exceptions.AttributeValueInvalid
- `TestKeyPairAttributes::test_ec_keypair_attributes`: pkcs11.exceptions.AttributeValueInvalid
- ... and 3 more

**test_object_search_patterns.py** (7 tests):
- `TestSearchByID::test_find_key_by_id`: pkcs11.exceptions.FunctionNotSupported
- `TestSearchByID::test_search_by_id_and_class`: pkcs11.exceptions.FunctionNotSupported
- `TestKeypairIDLinkage::test_rsa_keypair_same_id`: pkcs11.exceptions.AttributeValueInvalid
- `TestKeypairIDLinkage::test_find_keypair_by_id`: pkcs11.exceptions.AttributeValueInvalid
- `TestKeypairIDLinkage::test_find_all_by_id`: pkcs11.exceptions.AttributeValueInvalid
- `TestMultiAttributeSearch::test_search_by_label_and_type`: pkcs11.exceptions.FunctionNotSupported
- `TestMultiAttributeSearch::test_search_filters_correctly`: pkcs11.exceptions.FunctionNotSupported

**test_object_size.py** (2 tests):
- `TestObjectSize::test_aes_key_has_size`: pkcs11.exceptions.FunctionNotSupported
- `TestObjectSize::test_rsa_key_larger_than_aes`: pkcs11.exceptions.FunctionNotSupported

**test_object_visibility.py** (5 tests):
- `TestSessionObjectLifecycle::test_session_object_gone_after_close`: pkcs11.exceptions.FunctionNotSupported
- `TestSessionObjectLifecycle::test_session_data_object_gone_after_close`: AssertionError: Session data object survived session close assert 1 == 0  +  where 1 = len([<pkcs11._pkcs11.Object object at 0x7424dd2717f0>])
- `TestSessionObjectLifecycle::test_session_object_exists_while_session_open`: pkcs11.exceptions.FunctionNotSupported
- `TestTokenPrivateInteraction::test_public_session_obj_visible_same_session`: pkcs11.exceptions.AttributeValueInvalid
- `TestSessionObjectCrossVisibility::test_session_object_gone_when_creating_session_closes`: AssertionError: Session object survived owning session close assert 1 == 0  +  where 1 = len([<pkcs11._pkcs11.Object object at 0x7424dd1b6930>])

**test_padding_oracle.py** (4 tests):
- `TestRSAPaddingOracle::test_pkcs1v15_error_uniformity`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAPaddingOracle::test_oaep_error_uniformity`: pkcs11.exceptions.AttributeValueInvalid
- `TestAESPaddingOracle::test_cbc_pad_error_uniformity`: pkcs11.exceptions.FunctionNotSupported
- `TestTimingBasic::test_rsa_decrypt_timing_sanity`: pkcs11.exceptions.AttributeValueInvalid

**test_protocol_edge_cases.py** (1 tests):
- `TestResourceExhaustion::test_many_session_objects`: pkcs11.exceptions.FunctionNotSupported

**test_resource.py** (7 tests):
- `TestMemoryLeaks::test_key_generation_no_leak`: pkcs11.exceptions.FunctionNotSupported
- `TestMemoryLeaks::test_encrypt_cycle_no_leak`: pkcs11.exceptions.FunctionNotSupported
- `TestUseAfterDestroy::test_encrypt_after_destroy`: pkcs11.exceptions.FunctionNotSupported
- `TestUseAfterDestroy::test_sign_after_destroy`: pkcs11.exceptions.AttributeValueInvalid
- `TestUseAfterDestroy::test_double_destroy`: pkcs11.exceptions.FunctionNotSupported
- `TestUseAfterDestroy::test_read_attribute_after_destroy`: pkcs11.exceptions.FunctionNotSupported
- `TestBulkOperations::test_100_keys_coexist`: pkcs11.exceptions.FunctionNotSupported

**test_ro_session.py** (3 tests):
- `TestROSessionOperations::test_find_objects_in_ro_session`: pkcs11.exceptions.FunctionNotSupported
- `TestROSessionOperations::test_verify_in_ro_session`: pkcs11.exceptions.AttributeValueInvalid
- `TestSessionObjectLifecycle::test_session_object_gone_after_close`: pkcs11.exceptions.FunctionNotSupported

**test_ro_session_restrictions.py** (2 tests):
- `TestROTokenObjectCreation::test_generate_key_token_true_in_ro_fails`: pkcs11.exceptions.FunctionNotSupported
- `TestROExactCKR::test_generate_key_token_returns_session_read_only`: pkcs11.exceptions.FunctionNotSupported

**test_rsa_key_import.py** (2 tests):
- `TestRSAPrivateKeyImport::test_import_rsa_private_key`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAPrivateKeyImport::test_imported_private_key_signs`: pkcs11.exceptions.AttributeValueInvalid

**test_rsa_key_wrapping.py** (1 tests):
- `TestRSAPKCSWrap::test_wrapped_key_is_different_each_time`: pkcs11.exceptions.AttributeValueInvalid

**test_rsa_oaep.py** (7 tests):
- `TestRSAOAEPRoundtrip::test_oaep_encrypt_decrypt`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAOAEPRoundtrip::test_oaep_randomized`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAOAEPRoundtrip::test_oaep_empty_plaintext`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAOAEPRoundtrip::test_oaep_max_plaintext`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAOAEPRoundtrip::test_oaep_ciphertext_size`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAOAEPCrossVerify::test_encrypt_crypto_decrypt_p11`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSAOAEPCrossVerify::test_wrong_key_decrypt_fails`: pkcs11.exceptions.AttributeValueInvalid

**test_search.py** (8 tests):
- `TestObjectSearch::test_find_by_label`: pkcs11.exceptions.FunctionNotSupported
- `TestObjectSearch::test_find_by_class`: pkcs11.exceptions.FunctionNotSupported
- `TestObjectSearch::test_find_by_multiple_attributes`: pkcs11.exceptions.FunctionNotSupported
- `TestObjectSearch::test_find_all_objects`: pkcs11.exceptions.FunctionNotSupported
- `TestObjectSearch::test_find_many_objects`: pkcs11.exceptions.FunctionNotSupported
- `TestObjectSearch::test_find_after_destroy`: pkcs11.exceptions.FunctionNotSupported
- `TestKeyPairSearch::test_find_public_key`: pkcs11.exceptions.AttributeValueInvalid
- `TestKeyPairSearch::test_find_private_key`: pkcs11.exceptions.AttributeValueInvalid

**test_sensitivity.py** (8 tests):
- `TestSensitiveKeyValue::test_sensitive_aes_value_not_readable`: pkcs11.exceptions.FunctionNotSupported
- `TestSensitiveKeyValue::test_non_sensitive_aes_value_readable`: pkcs11.exceptions.FunctionNotSupported
- `TestSensitiveKeyValue::test_sensitive_rsa_private_exponent_not_readable`: pkcs11.exceptions.AttributeValueInvalid
- `TestExtractableEnforcement::test_non_extractable_by_default`: pkcs11.exceptions.FunctionNotSupported
- `TestExtractableEnforcement::test_extractable_when_requested`: pkcs11.exceptions.FunctionNotSupported
- `TestSensitiveFlag::test_sensitive_flag_is_true_by_default`: pkcs11.exceptions.FunctionNotSupported
- `TestSensitiveFlag::test_sensitive_flag_settable_at_creation`: pkcs11.exceptions.FunctionNotSupported
- `TestSensitiveFlag::test_always_sensitive_flag`: pkcs11.exceptions.FunctionNotSupported

**test_session_edge_cases.py** (3 tests):
- `TestCloseAllSessions::test_close_all_sessions`: pkcs11.exceptions.FunctionNotSupported
- `TestSoftHSM2IssueRegressions::test_wrap_unsupported_mechanism_returns_proper_ckr`: pkcs11.exceptions.FunctionNotSupported
- `TestSoftHSM2IssueRegressions::test_rsa_keygen_minimum_size`: pkcs11.exceptions.AttributeValueInvalid

**test_session_exhaustion.py** (1 tests):
- `TestSessionExhaustion::test_open_many_sessions`: pkcs11.exceptions.FunctionNotSupported

**test_session_info.py** (1 tests):
- `TestSessionInfo::test_session_has_token`: pkcs11.exceptions.FunctionNotSupported

**test_session_state_machine.py** (13 tests):
- `TestLoginStateTransitions::test_login_user_enables_private_access`: pkcs11.exceptions.FunctionNotSupported
- `TestLoginStateTransitions::test_logout_returns_to_public`: pkcs11.exceptions.FunctionNotSupported
- `TestLoginStateTransitions::test_login_logout_login_cycle`: pkcs11.exceptions.FunctionNotSupported
- `TestConcurrentSessionLogin::test_logout_affects_all_sessions`: pkcs11.exceptions.FunctionNotSupported
- `TestLogoutEffects::test_private_session_key_invisible_after_logout`: pkcs11.exceptions.FunctionNotSupported
- `TestLogoutEffects::test_public_object_remains_after_logout`: pkcs11.exceptions.AttributeValueInvalid
- `TestSessionCloseEffects::test_close_session_destroys_its_session_objects`: pkcs11.exceptions.FunctionNotSupported
- `TestSessionCloseEffects::test_token_object_survives_session_close`: pkcs11.exceptions.FunctionNotSupported
- `TestROvsRWSessionState::test_ro_session_cannot_create_token_objects`: pkcs11.exceptions.FunctionNotSupported
- `TestROvsRWSessionState::test_ro_session_can_digest`: pkcs11.exceptions.UserNotLoggedIn
- ... and 3 more

**test_set_attribute.py** (7 tests):
- `TestSetAttributePositive::test_change_label`: pkcs11.exceptions.FunctionNotSupported
- `TestSetAttributePositive::test_change_id`: pkcs11.exceptions.FunctionNotSupported
- `TestSetAttributePositive::test_change_label_on_keypair`: pkcs11.exceptions.AttributeValueInvalid
- `TestSetAttributeNegative::test_cannot_change_class`: pkcs11.exceptions.FunctionNotSupported
- `TestSetAttributeNegative::test_cannot_change_key_type`: pkcs11.exceptions.FunctionNotSupported
- `TestSetAttributeNegative::test_cannot_change_modulus`: pkcs11.exceptions.AttributeValueInvalid
- `TestSetAttributeNegative::test_cannot_set_value_on_sensitive_key`: pkcs11.exceptions.FunctionNotSupported

**test_sign.py** (16 tests):
- `TestRSASignature::test_rsa_generate_keypair`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSASignature::test_rsa_pkcs_sign_verify`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSASignature::test_rsa_sign_wrong_data_fails_verify`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSASignature::test_rsa_hash_mechanisms[SHA256]`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSASignature::test_rsa_hash_mechanisms[SHA384]`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSASignature::test_rsa_hash_mechanisms[SHA512]`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSASignature::test_rsa_pss_sign_verify`: pkcs11.exceptions.AttributeValueInvalid
- `TestRSASignature::test_rsa_different_keys_different_signatures`: pkcs11.exceptions.AttributeValueInvalid
- `TestECDSASignature::test_ec_generate_keypair`: pkcs11.exceptions.AttributeValueInvalid
- `TestECDSASignature::test_ecdsa_sign_verify`: pkcs11.exceptions.AttributeValueInvalid
- ... and 6 more

**test_stateful.py** (1 tests):
- `test_pkcs11_stateful`: pkcs11.exceptions.FunctionNotSupported

**test_stress.py** (4 tests):
- `TestMultiSessionConcurrency::test_sequential_multi_session`: pkcs11.exceptions.FunctionNotSupported
- `TestRapidOperations::test_rapid_encrypt_decrypt_1000`: pkcs11.exceptions.FunctionNotSupported
- `TestRapidOperations::test_rapid_sign_verify_100`: pkcs11.exceptions.AttributeValueInvalid
- `TestSessionStress::test_create_destroy_cycle`: pkcs11.exceptions.FunctionNotSupported

**test_subprocess_safety.py** (1 tests):
- `TestForkSafety::test_fork_after_initialize`: subprocess.TimeoutExpired: Command '['/app/.venv/bin/python', '-c', '\nimport os, pkcs11\nlib = pkcs11.lib("/usr/lib64/pkcs11/libtpm2_pkcs11.so")\nlib.initialize()\npid = os.fork()\nif pid == 0:\n

**test_surface_audit.py** (2 tests):
- `TestMechanismFlagsConsistency::test_aes_encrypt_flag_matches_capability`: pkcs11.exceptions.FunctionNotSupported
- `TestMechanismFlagsConsistency::test_key_size_range_respected`: pkcs11.exceptions.FunctionNotSupported

**test_threading.py** (1 tests):
- `TestThreadedOperations::test_threaded_random`: pkcs11.exceptions.GeneralError

**test_tookan.py** (3 tests):
- `TestConflictingUsageAttrs::test_wrap_and_decrypt_on_same_key`: pkcs11.exceptions.FunctionNotSupported
- `TestConflictingUsageAttrs::test_encrypt_and_unwrap_on_same_key`: pkcs11.exceptions.FunctionNotSupported
- `TestSensitivePreservation::test_sensitive_preserved_on_copy`: pkcs11.exceptions.FunctionNotSupported

**test_tool_templates.py** (4 tests):
- `TestDefaultToolTemplates::test_pkcs11_tool_rsa_defaults`: pkcs11.exceptions.AttributeValueInvalid
- `TestDefaultToolTemplates::test_pkcs11_tool_aes_defaults`: pkcs11.exceptions.FunctionNotSupported
- `TestConcurrentFindObjects::test_find_during_sequential_create_destroy`: pkcs11.exceptions.FunctionNotSupported
- `TestDBStress::test_rapid_keygen_destroy_500`: pkcs11.exceptions.FunctionNotSupported

**test_wycheproof.py** (296 tests):
- `TestAESGCMWycheproof::test_aes_gcm[tc6-valid]`: pkcs11.exceptions.GeneralError
- `TestAESGCMWycheproof::test_aes_gcm[tc7-valid]`: pkcs11.exceptions.GeneralError
- `TestAESGCMWycheproof::test_aes_gcm[tc8-valid]`: pkcs11.exceptions.GeneralError
- `TestAESGCMWycheproof::test_aes_gcm[tc9-valid]`: pkcs11.exceptions.GeneralError
- `TestAESGCMWycheproof::test_aes_gcm[tc10-valid]`: pkcs11.exceptions.GeneralError
- `TestAESGCMWycheproof::test_aes_gcm[tc11-valid]`: pkcs11.exceptions.GeneralError
- `TestAESGCMWycheproof::test_aes_gcm[tc12-valid]`: pkcs11.exceptions.GeneralError
- `TestAESGCMWycheproof::test_aes_gcm[tc13-valid]`: pkcs11.exceptions.GeneralError
- `TestAESGCMWycheproof::test_aes_gcm[tc14-valid]`: pkcs11.exceptions.GeneralError
- `TestAESGCMWycheproof::test_aes_gcm[tc15-valid]`: pkcs11.exceptions.GeneralError
- ... and 286 more

**test_lifecycle.py** (1 tests):
- `TestCertificateLifecycle::test_cert_modifiability`: Failed: Successfully modified label on non-modifiable certificate

### pkcs11-mock (77 failures, 5 errors)

pkcs11-mock is a minimal v3.1 stub with limited mechanism support. Most failures are
expected: `MechanismInvalid` (no AES/RSA support), `SessionCount` (session management),
and `AttributeValueInvalid` (no RSA keygen). These are not actionable.

Notable failures that may indicate test issues:

- `TestCKRPinErrors::test_ckr_pin_incorrect`: Failed: DID NOT RAISE <class 'pkcs11.exceptions.PinIncorrect'>
- `TestFindObjectsErrors::test_find_by_class`: assert 0 >= 1  +  where 0 = len([])
- `TestKeyFunctionNotPermitted::test_encrypt_not_permitted`: AssertionError: Crash: Traceback (most recent call last):     File "<string>", line 44, in <module>   AssertionError: GenKey: 0x00000070 assert 1 == 0
- `TestKeyFunctionNotPermitted::test_sign_not_permitted`: AssertionError: Crash: Traceback (most recent call last):     File "<string>", line 44, in <module>   AssertionError: GenKey: 0x00000070 assert 1 == 0
- `TestKeyFunctionNotPermitted::test_decrypt_not_permitted`: AssertionError: Crash: Traceback (most recent call last):     File "<string>", line 43, in <module>   AssertionError: GenKey: 0x00000070 assert 1 == 0
- `TestBufferTooSmall::test_digest_buffer_too_small`: AssertionError: Crash: Traceback (most recent call last):     File "<string>", line 23, in <module>   AssertionError: DigestInit: 0x00000070 assert 1 == 0
- `TestBufferTooSmall::test_encrypt_buffer_too_small`: AssertionError: Crash: Traceback (most recent call last):     File "<string>", line 38, in <module>   AssertionError: GenKey: 0x00000070 assert 1 == 0
- `TestOperationActive::test_double_encrypt_init`: AssertionError: Crash: Traceback (most recent call last):     File "<string>", line 64, in <module>   AssertionError: GenerateKey failed: 0x00000070 assert 1 == 0
- `TestOperationActive::test_encrypt_then_sign_init`: AssertionError: Crash: Traceback (most recent call last):     File "<string>", line 64, in <module>   AssertionError: GenerateKey failed: 0x00000070 assert 1 == 0
- `TestOperationActive::test_double_digest_init`: AssertionError: Crash: Traceback (most recent call last):     File "<string>", line 64, in <module>   AssertionError: GenerateKey failed: 0x00000070 assert 1 == 0
- `TestOperationActive::test_double_sign_init`: AssertionError: Crash: Traceback (most recent call last):     File "<string>", line 64, in <module>   AssertionError: GenerateKey failed: 0x00000070 assert 1 == 0
- `TestOperationActive::test_double_decrypt_init`: AssertionError: Crash: Traceback (most recent call last):     File "<string>", line 64, in <module>   AssertionError: GenerateKey failed: 0x00000070 assert 1 == 0
- `TestLoginErrors::test_wrong_pin`: Failed: DID NOT RAISE <class 'pkcs11.exceptions.PinIncorrect'>
- `TestCKRTemplateCompliance::test_missing_class_returns_template_incomplete`: Failed: Should have raised for missing CKA_CLASS
- `TestCKRTemplateCompliance::test_invalid_class_returns_attribute_value_invalid`: Failed: Should have raised for invalid CLASS

---

## Appendix A: Skip Reasons Summary

Top 5 skip reasons per provider.

### bouncyhsm

| Count | Reason |
|-------|--------|
| 2,095 | Cannot decode asn ECDH vector: ValueError |
| 1,558 | PKCS5_PBKD2 not supported |
| 1,512 | DSA_SHA256 not supported |
| 520 | Cannot decode pem ECDH vector: ValueError |
| 445 | DSA_SHA224 not supported |

### kryoptic

| Count | Reason |
|-------|--------|
| 8,055 | Cannot import EC private key for ECDH |
| 4,629 | Cannot import EC key for secp256k1: AttributeValueInvalid |
| 4,485 | Cannot import EC key for secp224r1: AttributeValueInvalid |
| 2,095 | Cannot decode asn ECDH vector: ValueError |
| 1,512 | DSA_SHA256 not supported |

### kryoptic-fips

| Count | Reason |
|-------|--------|
| 8,055 | Cannot import EC private key for ECDH |
| 4,629 | Cannot import EC key for secp256k1: AttributeValueInvalid |
| 4,485 | Cannot import EC key for secp224r1: AttributeValueInvalid |
| 2,095 | Cannot decode asn ECDH vector: ValueError |
| 1,512 | DSA_SHA256 not supported |

### kryoptic-main

| Count | Reason |
|-------|--------|
| 8,055 | Cannot import EC private key for ECDH |
| 4,629 | Cannot import EC key for secp256k1: AttributeValueInvalid |
| 4,485 | Cannot import EC key for secp224r1: AttributeValueInvalid |
| 2,095 | Cannot decode asn ECDH vector: ValueError |
| 1,512 | DSA_SHA256 not supported |

### nss

| Count | Reason |
|-------|--------|
| 6,093 | Cannot import EC private key for ECDH |
| 4,629 | Cannot import EC key for secp256k1: DomainParamsInvalid |
| 4,485 | Cannot import EC key for secp224r1: DomainParamsInvalid |
| 2,095 | Cannot decode asn ECDH vector: ValueError |
| 1,992 | Cannot import Montgomery private key |

### nss-main

| Count | Reason |
|-------|--------|
| 6,093 | Cannot import EC private key for ECDH |
| 4,629 | Cannot import EC key for secp256k1: DomainParamsInvalid |
| 4,485 | Cannot import EC key for secp224r1: DomainParamsInvalid |
| 2,095 | Cannot decode asn ECDH vector: ValueError |
| 1,992 | Cannot import Montgomery private key |

### nss-pqc

| Count | Reason |
|-------|--------|
| 6,093 | Cannot import EC private key for ECDH |
| 4,629 | Cannot import EC key for secp256k1: DomainParamsInvalid |
| 4,485 | Cannot import EC key for secp224r1: DomainParamsInvalid |
| 2,095 | Cannot decode asn ECDH vector: ValueError |
| 1,992 | Cannot import Montgomery private key |

### opencryptoki

| Count | Reason |
|-------|--------|
| 4,064 | Cannot import Montgomery private key |
| 2,095 | Cannot decode asn ECDH vector: ValueError |
| 1,558 | PKCS5_PBKD2 not supported |
| 1,512 | DSA_SHA256 not supported |
| 1,271 | Cannot import EC key for secp224k1: CurveNotSupported |

### pkcs11-mock

| Count | Reason |
|-------|--------|
| 10 | Requires v32, module has v3.1 |
| 5 | fault-proxy not built (run: bash local-builds/build.sh fault-proxy) |
| 4 | Destructive test (use --p11-destructive to enable |
| 2 | AES_CBC_PAD not supported |
| 2 | EC key gen not supported |

### softhsm2

| Count | Reason |
|-------|--------|
| 4,064 | Cannot import Montgomery private key |
| 2,095 | Cannot decode asn ECDH vector: ValueError |
| 1,558 | PKCS5_PBKD2 not supported |
| 714 | Requires v30, module has v2.40 |
| 695 | Requires v32, module has v2.40 |

### softhsm2-main

| Count | Reason |
|-------|--------|
| 4,064 | Cannot import Montgomery private key |
| 2,092 | Cannot decode asn ECDH vector: ValueError |
| 1,558 | PKCS5_PBKD2 not supported |
| 714 | Requires v30, module has v2.40 |
| 695 | Requires v32, module has v2.40 |

### tpm2

| Count | Reason |
|-------|--------|
| 21,735 | ECDH1_DERIVE not supported |
| 4,629 | Cannot import EC key for secp256k1: AttributeValueInvalid |
| 4,485 | Cannot import EC key for secp224r1: AttributeValueInvalid |
| 3,480 | Cannot import EC key for secp384r1: AttributeValueInvalid |
| 2,894 | Cannot import EC key for secp256r1: AttributeValueInvalid |

---

## Appendix B: XFail Summary

XFail reasons appearing 10+ times across all providers.

**Total xfails across all providers:** 21,751

| Count | Reason |
|-------|--------|
| 1,080 | PBES2 key derivation unsupported (various PRF/keylen combinations) |
| 246 | HMAC failed: GeneralError |
| 132 | HMAC failed: KeyHandleInvalid |
| 54 | Module cannot import 32-byte HMAC key |
| 48 | HMAC failed: KeySizeRange |
| 45 | Kryoptic returns CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID |
| 18 | CKM_SP800_108_FEEDBACK_KDF derivation not operational:  |
| 15 | CKM_RSA_AES_KEY_WRAP wrap not functional:  |
| 12 | Module limitation: 16-byte key too short for SHA256_HMAC (KeySizeRange) |
| 10 | Module exposes v3.0 interface but C_LoginUser returns CKR_FUNCTION_NOT_SUPPORTED |
| 10 | Module does not implement C_LoginUser (CKR_FUNCTION_NOT_SUPPORTED) |

The remaining ~19,000 xfails are from Wycheproof ECDH/ECDSA/RSA/AES/DSA/ChaCha20/HKDF vectors
where individual modules cannot import keys, lack mechanism support, or return non-standard
error codes for specific test vectors. Each has a specific `wasxfail` message identifying
the exact vector and error.
