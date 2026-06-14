# opencryptoki-master — Per-Failure Triage

**Effective records:** 544
**Categories:** {'PROVIDER_BUG': 412, 'UNKNOWN': 83, 'SOFT_TOKEN_CAVEAT': 43, 'KNOWN_ISSUE': 5, 'UPSTREAM_BUG': 1}
**Severities:** {'LOW': 254, 'HIGH': 178, 'MEDIUM': 107, 'INFO': 5}

## Findings (456)

Ordered by severity then category.

### `test_acvp_eddsa.py` (4 findings)

#### F001 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:2170557c50cd8be2`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::TestEdDsaKeyVer::test_eddsa_keyver[EDDSA-KeyVer-ED-25519-tc1]`
- **Message:** Failed: EDDSA-KeyVer-ED-25519-tc1: Module ACCEPTED an INVALID EdDSA key
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F002 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:f1758660a1420a12`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::TestEdDsaKeyVer::test_eddsa_keyver[EDDSA-KeyVer-ED-25519-tc4]`
- **Message:** Failed: EDDSA-KeyVer-ED-25519-tc4: Module ACCEPTED an INVALID EdDSA key
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F003 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:10d14b2106e13b07`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::TestEdDsaKeyVer::test_eddsa_keyver[EDDSA-KeyVer-ED-448-tc6]`
- **Message:** Failed: EDDSA-KeyVer-ED-448-tc6: Module ACCEPTED an INVALID EdDSA key
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F004 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:36e9b8f6d750b6fd`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::TestEdDsaKeyVer::test_eddsa_keyver[EDDSA-KeyVer-ED-448-tc8]`
- **Message:** Failed: EDDSA-KeyVer-ED-448-tc8: Module ACCEPTED an INVALID EdDSA key
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

### `test_ckr_derive.py` (1 findings)

#### F005 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:14415d9bf464c52c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_derive.py::TestDeriveKeyErrors::test_key_type_inconsistent`
- **Message:** _pytest.outcomes.XFailed: C_DeriveKey(base_key_type_wrong_for_mechanism): rejected with CKR_MECHANISM_PARAM_INVALID, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.14.5]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_DeriveKey(base_key_type_wrong_for_mechanism): rejected with CKR_MECHANISM_PARAM_INVALID, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.14.5]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_kem.py` (1 findings)

#### F006 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1f7f30683ed937d0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_kem.py::TestEncapsulateKeyErrors::test_key_type_inconsistent`
- **Message:** _pytest.outcomes.XFailed: C_EncapsulateKey(RSA_key_with_ML_KEM_mechanism): rejected with CKR_KEY_FUNCTION_NOT_PERMITTED, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.2 Sec.5.14.7]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_EncapsulateKey(RSA_key_with_ML_KEM_mechanism): rejected with CKR_KEY_FUNCTION_NOT_PERMITTED, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.2 Sec.5.14.7]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_object.py` (1 findings)

#### F007 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d4a33aa2cd207b29#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_object.py::TestCreateObjectErrors::test_allowed_mechanisms_empty_null_pointer_enforced`
- **Message:** Failed: CKA_ALLOWED_MECHANISMS empty-array enforcement for C_EncryptInit/C_Encrypt: claimed the protection then violated it (self-contradiction)
- **Evidence:** CKA_ALLOWED_MECHANISMS empty-array enforcement: key created with CKA_ALLOWED_MECHANISMS=[] (empty array = no mechanisms permitted), yet C_EncryptInit/C_Encrypt succeeds. policy attribute self-contradiction - module claimed the protection (empty allowed-mechanisms list) then violated it by allowing encrypt. PKCS#11 v3.1 Sec.4.6.4: CKA_ALLOWED_MECHANISMS restricts which mechanisms can be used with the key.

### `test_ckr_raw_buffer.py` (4 findings)

#### F008 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0115a21f7a210763`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestDecryptBufferTooSmallGuards::test_aes_cbc_pad_decrypt_buffer_too_small_preserves_guard_and_retries`
- **Message:** Failed: C_Decrypt AES-CBC-PAD undersized output buffer guard: subprocess failed with exit code 1
stdout: CKR:0x00000000
LEN:14
OVERWRITTEN:13
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

#### F009 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c2c0eec2e30695af`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestDecryptBufferTooSmallGuards::test_aes_cbc_pad_decrypt_final_buffer_too_small_preserves_guard_and_retries`
- **Message:** Failed: C_DecryptFinal AES-CBC-PAD undersized output buffer guard: subprocess failed with exit code 1
stdout: CKR:0x00000000
LEN:15
OVERWRITTEN:14
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

#### F010 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9386b83904ee71f1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestBufferTooSmall::test_digest_buffer_too_small`
- **Message:** _pytest.outcomes.XFailed: C_Digest returned CKR_OK for a 1-byte output buffer without writing past it (PKCS#11 §5.10.2 expects CKR_BUFFER_TOO_SMALL; clean return-code deviation, no buffer overflow)
- **Evidence:** Buffer-protocol deviation: C_Digest returned CKR_OK for a 1-byte output buffer without writing past it (PKCS#11 §5.10.2 expects CKR_BUFFER_TOO_SMALL; clean return-code deviation, no buffer overflow).

#### F011 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:95e3dc193f3c808d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestDecryptBufferTooSmallGuards::test_aes_cbc_pad_decrypt_update_buffer_too_small_preserves_guard_and_retries`
- **Message:** _pytest.outcomes.XFailed: C_DecryptUpdate returned CKR_BUFFER_TOO_SMALL but did not report a usable retry length
- **Evidence:** Buffer-protocol deviation: C_DecryptUpdate returned CKR_BUFFER_TOO_SMALL but did not report a usable retry length.

### `test_ckr_spec_compliance.py` (1 findings)

#### F012 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:60e72aa820eb2463#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_spec_compliance.py::TestCKRTemplateCompliance::test_invalid_class_returns_attribute_value_invalid`
- **Message:** _pytest.outcomes.XFailed: C_CreateObject(bad CLASS): rejected with CKR_ATTRIBUTE_TYPE_INVALID, expected ['CKR_ATTRIBUTE_VALUE_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_CreateObject(bad CLASS): rejected with CKR_ATTRIBUTE_TYPE_INVALID, expected ['CKR_ATTRIBUTE_VALUE_INVALID']. Direction = reject-valid → functional gap (LOW).

### `test_api_security.py` (1 findings)

#### F013 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:833a1660b6f6245e#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_api_security.py::TestSensitiveExtraction::test_private_key_not_extractable`
- **Message:** AssertionError: SECURITY: CKA_PRIVATE_EXPONENT readable -- private key material exposed
assert <CKA_PRIVATE_EXPONENT: 0x00000123> not in {<CKA_PRIVATE_EXPONENT: 0x00000123>: b'-\x1e\x83\x97\xcf\xd9=Eo\x07\x01\';\xc9}w\xb7%\xa5!\xff\xfd\xbdm\xe4\x15\x91\x1...\\xb4EQ\xf6\xa8U\xf5\xe1\x1d\xec\x12\x9a,\
- **Evidence:** Generated RSA private key (template omits CKA_SENSITIVE) exposes CKA_PRIVATE_EXPONENT. Per PKCS#11 v3.1 Sec.4.6.3, the default CKA_SENSITIVE for a generated private key is FALSE on tokens that support extractable keys - so the spec ALLOWS this. opencryptoki soft token uses the spec-default (insecure) value. Test does not set CKA_SENSITIVE=True. Same behavior observed on bouncyhsm. Recommend tightening the test to set CKA_SENSITIVE=True for a meaningful security check; this is a soft-token caveat

### `test_arithmetic_overflow.py` (4 findings)

#### F014 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:dcca930e6b3f6a8a`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestTemplateCountOverflow::test_template_count_overflow[find_objects_init-ulong_max]`
- **Message:** Failed: C_FindObjectsInit(template_count=0x100000000): module crashed with signal 7
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F015 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:d793c142509b47f1`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestTemplateCountOverflowValidHandles::test_template_count_overflow_with_valid_object_handle[get_attribute_value-ulong_max]`
- **Message:** Failed: C_GetAttributeValue(valid object, template_count=0x100000000): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F016 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:36d45cebbf7d3161`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestKemTemplateCountOverflow::test_kem_output_template_count_overflow[encapsulate_key-sizeof_attr_overflow]`
- **Message:** Failed: C_EncapsulateKey(ML-KEM output template_count=0xaaaaaaaaaaaaaab): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F017 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:49a30482ab185139`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestKemTemplateCountOverflow::test_kem_output_template_count_overflow[decapsulate_key-sizeof_attr_overflow]`
- **Message:** Failed: C_DecapsulateKey(ML-KEM output template_count=0xaaaaaaaaaaaaaab): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_cve_regression.py` (1 findings)

#### F018 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:17d13e3e162cdedd#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_cve_regression.py::TestTookanUnwrapAttrs::test_unwrapped_key_preserves_extractable`
- **Message:** AssertionError: Tookan: unwrapped key is EXTRACTABLE despite template saying False
assert True is False
- **Evidence:** Tookan unwrap attribute violation: C_UnwrapKey with template CKA_EXTRACTABLE=False produces a key whose CKA_EXTRACTABLE attribute reads True. policy attribute self-contradiction - module accepted the protection-claiming template then violated it. Root cause: opencryptoki ignores policy attributes (CKA_EXTRACTABLE/CKA_SENSITIVE) in unwrap templates (documented in docs/module-issues.md), so the unwrapped key inherits EXTRACTABLE from the wrapped blob (which was True). Security impact: key marked n

### `test_error_path_kwp.py` (1 findings)

#### F019 [HIGH/UPSTREAM_BUG] — 📚 DOCS_ONLY
- **Signature:** `sha1:8a409ca256cb898c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_error_path_kwp.py::TestCorruptedUnwrap::test_corrupted_unwrap[decrypt-kwp-aiv]`
- **Message:** Failed: CKM_AES_KEY_WRAP_KWP decrypt: corruption=aiv: subprocess failed with exit code 1
stdout: decrypt_rv=CKR_GENERAL_ERROR
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"C_GetSlot
- **Evidence:** AES-KWP buffer overwrite on corrupted input (AIV corruption): C_Decrypt on corrupted KWP blob returns CKR_GENERAL_ERROR and writes past the minimal output buffer (guard bytes overwritten). Root cause upstream in OpenSSL PR #30663 (AES-KW/KWP unwrap heap overflow on corrupted data); also tracked in OpenCryptoki PR #932. Bug-report target = OpenSSL, NOT opencryptoki.

### `test_ffi_length_boundary.py` (12 findings)

#### F020 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:d18764354e110e02`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_sign_isize_boundary[isize_max]`
- **Message:** Failed: C_Sign(HMAC_SHA256, ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F021 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:8016f608da302972`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_verify_isize_data_len[isize_max]`
- **Message:** Failed: C_Verify(HMAC_SHA256, ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F022 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:b4418cdb5f0181e1`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_digest_isize_boundary[isize_max]`
- **Message:** Failed: C_Digest(SHA256, ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F023 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:905931430b95f77b`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_digest_isize_boundary[isize_max_plus_1]`
- **Message:** Failed: C_Digest(SHA256, ulDataLen=0x8000000000000000): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F024 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:ff6769fcff626745`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[sign_update-isize_max]`
- **Message:** Failed: C_SignUpdate(ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_SignUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F025 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:c67434dafcd232cd`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[sign_update-isize_max_plus_1]`
- **Message:** Failed: C_SignUpdate(ulDataLen=0x8000000000000000): module crashed with signal 11
stdout: TARGET:C_SignUpdate
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F026 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:d46aba5c8a8f948b`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[verify_update-isize_max]`
- **Message:** Failed: C_VerifyUpdate(ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_VerifyUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F027 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:e8964bf7cf0ac883`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[verify_update-isize_max_plus_1]`
- **Message:** Failed: C_VerifyUpdate(ulDataLen=0x8000000000000000): module crashed with signal 11
stdout: TARGET:C_VerifyUpdate
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F028 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:1c645081a12e2515`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[digest_update-isize_max]`
- **Message:** Failed: C_DigestUpdate(ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_DigestUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F029 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:96dd7a4fa11228d4`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[digest_update-isize_max_plus_1]`
- **Message:** Failed: C_DigestUpdate(ulDataLen=0x8000000000000000): module crashed with signal 11
stdout: TARGET:C_DigestUpdate
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F030 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:74e999339d160cdc`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestMlDsaExplicitEmptyContext::test_mldsa_verify_empty_context_nonnull_pointer`
- **Message:** Failed: C_Verify(ML-DSA, pContext non-NULL, ulContextLen=0): module crashed with signal 6
stdout: 
stderr: free(): invalid size
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F031 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:8b1d3723479a5a37`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestGcmAadLengthBoundary::test_gcm_aad_length_boundary[isize_max]`
- **Message:** _pytest.outcomes.XFailed: C_Encrypt(AES_GCM, ulAADLen=0x7fffffffffffffff): rejected with CKR_FUNCTION_FAILED, expected ['CKR_ARGUMENTS_BAD', 'CKR_BUFFER_TOO_SMALL', 'CKR_DATA_LEN_RANGE', 'CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_padding_oracle.py` (2 findings)

#### F032 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6f8fb55460d43d91`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_padding_oracle.py::TestRSAPaddingOracle::test_oaep_error_uniformity`
- **Message:** Failed: SECURITY: RSA-OAEP padding oracle — non-uniform error codes: {'CKR_FUNCTION_FAILED', 'CKR_ENCRYPTED_DATA_INVALID'} (Manger 2001 attack vector). Distinct CKRs on invalid ciphertexts let an attacker partition decryption failures into categories — exactly the Manger leak channel.
- **Evidence:** Manger oracle: RSA-OAEP non-uniform errors. Real provider bug.

#### F033 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4a9ace15b588f40c`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_padding_oracle.py::TestAESPaddingOracle::test_cbc_pad_all_last_block_positions`
- **Message:** Failed: SECURITY: AES-CBC-PAD padding oracle (Vaudenay 2002) — distinct outcomes {'CKR_OK_DIFFERENT': 318, 'CKR_OK_MATCH': 2} across 320 corruption probes. An attacker with chosen-ciphertext access can recover plaintext byte-by-byte via ~256 oracle queries per byte. Mitigation is application-level:
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

### `test_parameter_validation.py` (9 findings)

#### F034 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:c6240b783f9d0cb4`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmTagSize::test_gcm_weak_tag_size[tag-8-bits]`
- **Message:** Failed: AES-GCM with 8-bit tag (below NIST 96-bit minimum): accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F035 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:cd67d8a2697abf10`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmTagSize::test_gcm_weak_tag_size[tag-32-bits]`
- **Message:** Failed: AES-GCM with 32-bit tag (below NIST 96-bit minimum): accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F036 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:b094c4ff1a35b7eb`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmTagSize::test_gcm_weak_tag_size[tag-64-bits]`
- **Message:** Failed: AES-GCM with 64-bit tag (below NIST 96-bit minimum): accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F037 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:fe005b755112c918`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmIvWeakness::test_gcm_weak_iv[single-zero-byte-iv]`
- **Message:** Failed: AES-GCM with 1-byte IV (below NIST 96-bit recommendation): accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F038 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:4fcd98a356c2afee`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmIvWeakness::test_gcm_weak_iv[4-zero-bytes-iv]`
- **Message:** Failed: AES-GCM with 4-byte IV (below NIST 96-bit recommendation): accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F039 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:05ae12e1af5d3d0f`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmIvReuse::test_gcm_iv_reuse_same_key`
- **Message:** Failed: AES-GCM IV reuse with the same key (NIST SP 800-38D requires unique IVs): accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F040 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:09c90034d0dea27a`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmTagSize::test_gcm_weak_tag_size[tag-0-bits]`
- **Message:** _pytest.outcomes.XFailed: AES-GCM with 0-bit tag (below NIST 96-bit minimum): rejected with CKR_GENERAL_ERROR, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F041 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:da3b449a9b22caf4#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestRsaExponent::test_rsa_weak_public_exponent[e=0]`
- **Message:** _pytest.outcomes.XFailed: RSA keygen with cryptographically invalid exponent e=0: rejected with CKR_TEMPLATE_INCOMPLETE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RSA keygen with cryptographically invalid exponent e=0: rejected with CKR_TEMPLATE_INCOMPLETE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEM. Direction = reject-valid → functional gap (LOW).

#### F042 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:faa1d2ecdb0cdd4e#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestEcPointValidation::test_ecdh_invalid_point[off-curve-point]`
- **Message:** _pytest.outcomes.XFailed: ECDH derive with infinity EC public point (invalid-curve attack): rejected with CKR_PUBLIC_KEY_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ECDH derive with infinity EC public point (invalid-curve attack): rejected with CKR_PUBLIC_KEY_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD',. Direction = reject-valid → functional gap (LOW).

### `test_recover_length_boundary.py` (1 findings)

#### F043 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:59dc86b0d702a23e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_recover_length_boundary.py::TestRecoverOutputLengthBoundary::test_verify_recover_one_byte_output_preserves_guard`
- **Message:** Failed: C_VerifyRecover one-byte output buffer guard: subprocess failed with exit code 1
stdout: P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_
- **Evidence:** C_VerifyRecover one-byte output buffer guard: after the size-query call (NULL output, returns CKR_OK), the verify-recover operation remains active - subsequent C_VerifyRecoverInit returns CKR_OPERATION_ACTIVE. Per PKCS#11 v3.1 general rule, C_VerifyRecover terminates unless CKR_BUFFER_TOO_SMALL; the size query returning CKR_OK should terminate. Note: spec is ambiguous on NULL-output size-query termination; NSS shows the same behavior (cross-provider pattern). Test cannot exercise the actual one-

### `test_aead.py` (1 findings)

#### F044 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e3fa276e0ec54c5b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_aead.py::TestAESGCMProviderGeneratedIV::test_gcm_generated_iv_strict_writeback_two_call`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **Evidence:** AES-GCM provider-generated IV convention (strict writeback, two-call form) returns CKR_FUNCTION_FAILED. Mechanism is advertised and mech-param is recognized, but the generated-IV encrypt path fails internally. Reject-valid with non-clean CKR - advertised convention not operational.

### `test_aes_modes.py` (3 findings)

#### F045 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4f15671d29e6f5e6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_aes_modes.py::TestAESCTR::test_aes_ctr_different_keys`
- **Message:** _pytest.outcomes.XFailed: CKM_AES_CTR advertised but encrypt is not operational: CKR_DATA_LEN_RANGE
- **Evidence:** Capability gap: CKM_AES_CTR advertised but encrypt is not operational: CKR_DATA_LEN_RANGE. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F046 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a3a38640c463af40#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_aes_modes.py::TestAESCTS::test_aes_cts_roundtrip`
- **Message:** _pytest.outcomes.XFailed: CKM_AES_CTS advertised but encrypt is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Capability gap: CKM_AES_CTS advertised but encrypt is not operational: CKR_MECHANISM_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F047 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:39f6e6acc5fccd94#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_aes_modes.py::TestAESCTR::test_aes_ctr_counter_bits_129_rejected`
- **Message:** _pytest.outcomes.XFailed: C_EncryptInit with ulCounterBits=129 (spec range 1-128): rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_EncryptInit with ulCounterBits=129 (spec range 1-128): rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

### `test_attribute_enforcement.py` (2 findings)

#### F048 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:467c341d1494a1e0#phase6`
- **Direction:** `WRONG_OUTPUT` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_attribute_enforcement.py::TestCheckValue::test_imported_key_kcv_matches_ecb_encrypt`
- **Message:** AssertionError: KCV mismatch: got , expected 66e94b
assert b'' == b'f\xe9K'
  
  Use -v to get more diff
- **Evidence:** opencryptoki returns CKR_OK for a secret-key import but CKA_CHECK_VALUE reads back empty (b'' instead of the expected 3-byte AES-CBC-ECB KCV '66e94b') (test_attribute_enforcement.py test_imported_key_kcv_matches_ecb_encrypt). The module does not compute/populate the key check value for imported keys. CKA_CHECK_VALUE (PKCS#11 v3.0 Sec.6.4) is a conformance/integrity convenience, not a crypto-correctness primitive; functional gap.

#### F049 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e5a82d823d29a099#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_attribute_enforcement.py::TestCheckValue::test_generated_key_has_check_value`
- **Message:** AssertionError: Expected 3-byte KCV, got 0 bytes
assert 0 == 3
 +  where 0 = len(b'')
- **Evidence:** After AES keygen, CKA_CHECK_VALUE (KCV) attribute returns 0 bytes instead of the expected 3-byte key check value. PKCS#11 v3.1 Sec.4.6.1: CKA_CHECK_VALUE is derived from encrypting a block of zeros with the key (first 3 bytes). Functional bug - KCV attribute not populated by keygen. No security impact (KCV is a non-secret verification value).

### `test_authenticated_wrap.py` (1 findings)

#### F050 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2d218d4b290218dd#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_authenticated_wrap.py::TestAuthenticatedWrap::test_aes_gcm_wrap_unwrap`
- **Message:** _pytest.outcomes.XFailed: AES-GCM authenticated generated-IV wrap rejected: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-GCM authenticated generated-IV wrap rejected: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK. Direction = reject-valid → functional gap (LOW).

### `test_buffers.py` (1 findings)

#### F051 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:732acb2f7f80082c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_buffers.py::TestOutputBufferEdgeCases::test_sign_final_buffer_too_small_then_correct`
- **Message:** AssertionError: Retry C_SignFinal with 256-byte buffer returned 0x00000091 — signature state was not preserved across BUFFER_TOO_SMALL
assert 145 == <CKR_OK: 0x00000000>
- **Evidence:** Retry C_SignFinal with 256-byte buffer (RSA-2048 correct size) returned CKR_BUFFER_TOO_SMALL (0x91) - signature operation state was NOT preserved across the initial CKR_BUFFER_TOO_SMALL. PKCS#11 v3.1 Sec.5.3: C_SignFinal returning CKR_BUFFER_TOO_SMALL must NOT terminate the operation; the retry with the reported size must succeed. lifecycle self-contradiction.

### `test_des.py` (3 findings)

#### F052 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1d798600d84eec83#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_des.py::TestDESEncryption::test_des_ofb64_roundtrip`
- **Message:** _pytest.outcomes.XFailed: CKM_DES_OFB64 advertised but rejected (OpenSSL 3 legacy provider absent): CKR_KEY_TYPE_INCONSISTENT
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CKM_DES_OFB64 advertised but rejected (OpenSSL 3 legacy provider absent): CKR_KEY_TYPE_INCONSISTENT. Direction = reject-valid → functional gap (LOW).

#### F053 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9c687ab5f740c097#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_des.py::TestDESEncryption::test_des_cfb8_roundtrip`
- **Message:** _pytest.outcomes.XFailed: CKM_DES_CFB8 advertised but rejected (OpenSSL 3 legacy provider absent): CKR_KEY_TYPE_INCONSISTENT
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CKM_DES_CFB8 advertised but rejected (OpenSSL 3 legacy provider absent): CKR_KEY_TYPE_INCONSISTENT. Direction = reject-valid → functional gap (LOW).

#### F054 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:19429aed6e41807a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_des.py::TestDESEncryption::test_des_cfb64_roundtrip`
- **Message:** _pytest.outcomes.XFailed: CKM_DES_CFB64 advertised but rejected (OpenSSL 3 legacy provider absent): CKR_KEY_TYPE_INCONSISTENT
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CKM_DES_CFB64 advertised but rejected (OpenSSL 3 legacy provider absent): CKR_KEY_TYPE_INCONSISTENT. Direction = reject-valid → functional gap (LOW).

### `test_dh_key_agreement.py` (1 findings)

#### F055 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:73084e4a40e49f4b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_dh_key_agreement.py::TestDHKeyAgreement::test_dh_pkcs_derive_rfc3526_group14_rejects_zero_value_len`
- **Message:** _pytest.outcomes.XFailed: CKM_DH_PKCS_DERIVE RFC 3526 Group 14 CKA_VALUE_LEN=0: rejected with CKR_TEMPLATE_INCONSISTENT, expected ['CKR_KEY_SIZE_RANGE', 'CKR_ATTRIBUTE_VALUE_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CKM_DH_PKCS_DERIVE RFC 3526 Group 14 CKA_VALUE_LEN=0: rejected with CKR_TEMPLATE_INCONSISTENT, expected ['CKR_KEY_SIZE_RANGE', 'CKR_ATTRIBUTE_VALUE_INVALID']. Direction = reject-valid → functional gap (LOW).

### `test_eddsa_public_key_encoding.py` (1 findings)

#### F056 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a678fbb542705a0b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_eddsa_public_key_encoding.py::test_eddsa_public_key_encoding_support`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **Evidence:** EdDSA mechanism is advertised (has_mechanism(EDDSA) returns True) but importing an EdDSA public key via C_CreateObject returns CKR_FUNCTION_FAILED. Reject-valid with non-clean CKR on advertised mechanism - EdDSA advertised but not operational. Same behavior on opencryptoki and opencryptoki-master.

### `test_errors.py` (1 findings)

#### F057 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:df022df96d433811`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_errors.py::TestEmptyInputs::test_encrypt_empty_data`
- **Message:** _pytest.outcomes.XFailed: C_Encrypt (length query) of empty data under AES-CBC-PAD: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_DATA_LEN_RANGE']
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

### `test_kem.py` (2 findings)

#### F058 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8b07ddfa7fc335b3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_kem.py::TestMLKEMDecapsulation::test_decapsulate_extractability_flags`
- **Message:** _pytest.outcomes.XFailed: ML-KEM security-flag decapsulate not operational: CKR_TEMPLATE_INCONSISTENT
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ML-KEM security-flag decapsulate not operational: CKR_TEMPLATE_INCONSISTENT. Direction = reject-valid → functional gap (LOW).

#### F059 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:71c36db908bd7952#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_kem.py::TestMLKEMNegative::test_decapsulate_invalid_ciphertext_length`
- **Message:** _pytest.outcomes.XFailed: ML-KEM invalid ciphertext length: rejected with CKR_TEMPLATE_INCONSISTENT, expected ['CKR_ENCRYPTED_DATA_LEN_RANGE', 'CKR_ENCRYPTED_DATA_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ML-KEM invalid ciphertext length: rejected with CKR_TEMPLATE_INCONSISTENT, expected ['CKR_ENCRYPTED_DATA_LEN_RANGE', 'CKR_ENCRYPTED_DATA_INVALID']. Direction = reject-valid → functional gap (LOW).

### `test_mech_attribute.py` (1 findings)

#### F060 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e69ab71bd491946e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_attribute.py::TestKeyAttributes::test_key_type_matches_template[SSL3_PRE_MASTER_KEY_GEN]`
- **Message:** _pytest.outcomes.XFailed: SSL3_PRE_MASTER_KEY_GEN keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SSL3_PRE_MASTER_KEY_GEN keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_mech_encrypt.py` (3 findings)

#### F061 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ee86651d952ed1ee`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[DES_CFB64]`
- **Message:** _pytest.outcomes.XFailed: DES_CFB64:encrypt: advertised but not operational (CKR_KEY_TYPE_INCONSISTENT)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F062 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:202867c82326bf00`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[DES_CFB8]`
- **Message:** _pytest.outcomes.XFailed: DES_CFB8:encrypt: advertised but not operational (CKR_KEY_TYPE_INCONSISTENT)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F063 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:22ad8788fdbd59b2`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[DES_OFB64]`
- **Message:** _pytest.outcomes.XFailed: DES_OFB64:encrypt: advertised but not operational (CKR_KEY_TYPE_INCONSISTENT)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_keygen.py` (1 findings)

#### F064 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:df6893bfc9a73529#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_keygen.py::TestMechKeygen::test_generate_key[SSL3_PRE_MASTER_KEY_GEN]`
- **Message:** _pytest.outcomes.XFailed: SSL3_PRE_MASTER_KEY_GEN keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SSL3_PRE_MASTER_KEY_GEN keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_mech_multipart.py` (8 findings)

#### F065 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c6402c2a716e18c5`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[DES_CFB64]`
- **Message:** _pytest.outcomes.XFailed: DES_CFB64:multipart-encrypt: advertised but not operational (CKR_KEY_TYPE_INCONSISTENT)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F066 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2cc703b559136ff8`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[DES_CFB8]`
- **Message:** _pytest.outcomes.XFailed: DES_CFB8:multipart-encrypt: advertised but not operational (CKR_KEY_TYPE_INCONSISTENT)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F067 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:399fc84a6fe13fbd`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[DES_OFB64]`
- **Message:** _pytest.outcomes.XFailed: DES_OFB64:multipart-encrypt: advertised but not operational (CKR_KEY_TYPE_INCONSISTENT)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F068 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:bdc632a958ba6d0f`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[AES_CTS]`
- **Message:** _pytest.outcomes.XFailed: AES_CTS:multipart-sign: advertised but not operational (CKR_FUNCTION_FAILED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F069 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7ca6699dc7487f1e`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[EDDSA]`
- **Message:** _pytest.outcomes.XFailed: EDDSA:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F070 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7f6bfd4682f34d97`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[HASH_ML_DSA]`
- **Message:** _pytest.outcomes.XFailed: HASH_ML_DSA:multipart-sign: advertised but not operational (CKR_FUNCTION_FAILED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F071 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7a2c128b0fcd321c`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[MD5_HMAC]`
- **Message:** _pytest.outcomes.XFailed: MD5_HMAC:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F072 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1551f419c0d82dc0`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[MD5_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: MD5_HMAC_GENERAL:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_negative.py` (125 findings)

#### F073 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:583fc355f4c90f92`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[AES_CMAC]`
- **Message:** Failed: AES_CMAC verify with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F074 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:ca047bbde2f172d1`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_derive_wrong_key_type[SHA1_KEY_DERIVATION]`
- **Message:** Failed: SHA1_KEY_DERIVATION derive with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F075 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:e359597cbb40a9d5`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_derive_wrong_key_type[SHA224_KEY_DERIVATION]`
- **Message:** Failed: SHA224_KEY_DERIVATION derive with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F076 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:30c32041911f3d33`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_derive_wrong_key_type[SHA256_KEY_DERIVATION]`
- **Message:** Failed: SHA256_KEY_DERIVATION derive with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F077 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:ee94578fc1e10434`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_derive_wrong_key_type[SHA384_KEY_DERIVATION]`
- **Message:** Failed: SHA384_KEY_DERIVATION derive with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F078 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:c712681677ca0b4b`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_derive_wrong_key_type[SHA3_224_KEY_DERIVE]`
- **Message:** Failed: SHA3_224_KEY_DERIVE derive with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F079 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:8ecb8c65d6258ff4`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_derive_wrong_key_type[SHA3_256_KEY_DERIVE]`
- **Message:** Failed: SHA3_256_KEY_DERIVE derive with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F080 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:de1caa70994d8162`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_derive_wrong_key_type[SHA3_384_KEY_DERIVE]`
- **Message:** Failed: SHA3_384_KEY_DERIVE derive with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F081 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:e3f82fd245e4b1d4`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_derive_wrong_key_type[SHA3_512_KEY_DERIVE]`
- **Message:** Failed: SHA3_512_KEY_DERIVE derive with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F082 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:68ef05af93e512d0`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_derive_wrong_key_type[SHA512_224_KEY_DERIVATION]`
- **Message:** Failed: SHA512_224_KEY_DERIVATION derive with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F083 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:eb01a0e256019873`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_derive_wrong_key_type[SHA512_256_KEY_DERIVATION]`
- **Message:** Failed: SHA512_256_KEY_DERIVATION derive with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F084 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:077527ff1e91ba72`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_derive_wrong_key_type[SHA512_KEY_DERIVATION]`
- **Message:** Failed: SHA512_KEY_DERIVATION derive with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F085 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:53a90200bcb81fb3`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_derive_wrong_key_type[SHAKE_128_KEY_DERIVE]`
- **Message:** Failed: SHAKE_128_KEY_DERIVE derive with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F086 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:aa7233ddd3ab048a`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_derive_wrong_key_type[SHAKE_256_KEY_DERIVE]`
- **Message:** Failed: SHAKE_256_KEY_DERIVE derive with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F087 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:926d43ce218d9b4e`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[EDDSA]`
- **Message:** Failed: EDDSA C_SignInit with missing required params: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F088 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:05bc886e92407eae#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 14
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_KEY_WRAP_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_WRAP_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_WRAP_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F089 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d98e2f03ad3e9211#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F090 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0e37f85cc39a1aae#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F091 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9795cc6cd0f825f0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_CFB128]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB128 keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB128 keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F092 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:03271bdb3fda819e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_CFB8]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB8 keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB8 keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F093 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c4939dcba36ffec8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F094 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0eab0f4fa8869f92#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_GCM]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_GCM keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F095 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6c74b4f18c29361d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_OFB]`
- **Message:** _pytest.outcomes.XFailed: AES_OFB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_OFB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F096 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e37a1fec2ff0b2ae#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_XTS]`
- **Message:** _pytest.outcomes.XFailed: AES_XTS keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_XTS keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F097 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5574dbc6b897f73e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES3_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F098 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b4b09dfffb1a527f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES3_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F099 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e42b52666e2275ea#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F100 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a9ab178e3f9e37d9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F101 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:19d7cbc6d4ee75fd#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES_CFB64]`
- **Message:** _pytest.outcomes.XFailed: DES_CFB64 keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CFB64 keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F102 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cf0b54c11fb5d45b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES_CFB8]`
- **Message:** _pytest.outcomes.XFailed: DES_CFB8 keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CFB8 keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F103 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8f5680563a809a83#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES_OFB64]`
- **Message:** _pytest.outcomes.XFailed: DES_OFB64 keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_OFB64 keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F104 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:94d5c04e15d2eac2#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[AES_MAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: AES_MAC_GENERAL C_SignInit with missing required params: rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_MAC_GENERAL C_SignInit with missing required params: rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F105 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3367784dc46d2db5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[DES3_CMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: DES3_CMAC_GENERAL C_SignInit with missing required params: rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CMAC_GENERAL C_SignInit with missing required params: rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F106 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a0a1e9703428605f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[DES3_MAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: DES3_MAC_GENERAL C_SignInit with missing required params: rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_MAC_GENERAL C_SignInit with missing required params: rejected with CKR_FUNCTION_FAILED, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F107 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4acd4cb15aa29542#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[MD5_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: MD5_HMAC_GENERAL C_SignInit with missing required params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: MD5_HMAC_GENERAL C_SignInit with missing required params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F108 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c9b55950e2f4c23c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F109 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4c87cc2f2d436671#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES3_ECB]`
- **Message:** _pytest.outcomes.XFailed: DES3_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F110 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:28fc02fb651b9f95#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES_ECB]`
- **Message:** _pytest.outcomes.XFailed: DES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F111 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:164f2d03befd8188#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA512_224_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA512_224_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_224_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F112 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:27c2f92d166e9b31#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA512_256_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA512_256_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_256_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F113 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4bbe8ac0e48b43db#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 7
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_KEY_WRAP_KWP]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_WRAP_KWP keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_WRAP_KWP keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F114 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8a738442ec6c100f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_KEY_WRAP]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_WRAP keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_WRAP keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F115 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:22bbef2b515630ce#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA224_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA224_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA224_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F116 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8a21969b43bb6675#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA256_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA256_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F117 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4e334e62da630475#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA384_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA384_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA384_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F118 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d303fab6d4a1d0dd#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_224_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_224_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_224_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F119 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6c7f720b111f7d9e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_256_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_256_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_256_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F120 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e2928c7d75ca1127#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_384_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_384_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_384_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F121 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e4efc6ed4bf98734#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_512_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_512_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_512_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F122 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:90a8bd596c5c162e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA512_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA512_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F123 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:627f59743ccefb05#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA_1_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA_1_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA_1_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F124 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:eea9cc572d597a95#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[HASH_ML_DSA]`
- **Message:** _pytest.outcomes.XFailed: HASH_ML_DSA C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: HASH_ML_DSA C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F125 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2a4eb2956b792fcf#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F126 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e9e9a916ac51e240#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA1_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA1_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA1_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F127 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2d5af7a806258837#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA224_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA224_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA224_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F128 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1f24d880f46403d2#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA256_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA256_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA256_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F129 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4f543da7450ce459#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA384_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA384_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA384_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F130 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:231fd5aea2f2c141#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_224_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA3_224_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_224_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F131 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f07c50bbc2d69be4#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_256_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA3_256_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_256_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F132 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3e491ea12a0ff8fa#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_384_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA3_384_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_384_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F133 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:76877a2ca3f8c668#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_512_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA3_512_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_512_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F134 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:36494d3a2505a642#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA512_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA512_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F135 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ecd95eb95284658d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_derive_missing_required_param[SHA3_224_KEY_DERIVE]`
- **Message:** _pytest.outcomes.XFailed: SHA3_224_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_224_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F136 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:16b3a901a1d17792#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_derive_missing_required_param[SHA3_256_KEY_DERIVE]`
- **Message:** _pytest.outcomes.XFailed: SHA3_256_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_256_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F137 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:13ac43b87e0a95e9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_derive_missing_required_param[SHA3_384_KEY_DERIVE]`
- **Message:** _pytest.outcomes.XFailed: SHA3_384_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_384_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F138 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:933c94f2caa5c48a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_derive_missing_required_param[SHA3_512_KEY_DERIVE]`
- **Message:** _pytest.outcomes.XFailed: SHA3_512_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_512_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F139 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b326e57feb9485d4#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_derive_missing_required_param[SHAKE_128_KEY_DERIVE]`
- **Message:** _pytest.outcomes.XFailed: SHAKE_128_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHAKE_128_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F140 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c4bf60f72b6114e1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_derive_missing_required_param[SHAKE_256_KEY_DERIVE]`
- **Message:** _pytest.outcomes.XFailed: SHAKE_256_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHAKE_256_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F141 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e7f9e6e8dd6ce4f7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[AES_CTS]`
- **Message:** _pytest.outcomes.XFailed: AES_CTS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F142 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:080a23f26d733add#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_verify_missing_required_param[AES_CTS]`
- **Message:** _pytest.outcomes.XFailed: AES_CTS C_VerifyInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTS C_VerifyInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F143 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:627a5819dd9d508f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_verify_missing_required_param[EDDSA]`
- **Message:** _pytest.outcomes.XFailed: EDDSA C_VerifyInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: EDDSA C_VerifyInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F144 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a8636dbc786872ce#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[AES_CMAC]`
- **Message:** _pytest.outcomes.XFailed: AES_CMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F145 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ce26ef4134b2c763#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[AES_CTS]`
- **Message:** _pytest.outcomes.XFailed: AES_CTS keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTS keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F146 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:df035f30f10dad1b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[AES_MAC]`
- **Message:** _pytest.outcomes.XFailed: AES_MAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_MAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F147 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2305448b20fd276e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[DES3_CMAC]`
- **Message:** _pytest.outcomes.XFailed: DES3_CMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F148 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e13439b9de6c1fa7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[DES3_MAC]`
- **Message:** _pytest.outcomes.XFailed: DES3_MAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_MAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F149 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:81c7812ff57bd77c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[MD5_HMAC]`
- **Message:** _pytest.outcomes.XFailed: MD5_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: MD5_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F150 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f1c50d93a47f9817#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA224_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA224_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA224_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F151 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:77d5109bb9c3100f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA256_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA256_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F152 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3d2dacf58b328b3b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA384_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA384_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA384_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F153 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0460ffb0272f3641#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA3_224_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA3_224_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_224_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F154 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cf2e884eae16b6b2#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA3_256_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA3_256_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_256_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F155 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0f454fe28dd0e9a8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA3_384_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA3_384_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_384_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F156 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1e92cd7b39fcd906#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA3_512_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA3_512_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_512_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F157 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f7a0578e65bf4c01#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA512_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA512_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F158 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6ff14d3fbca61a14#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA_1_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA_1_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA_1_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F159 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:abad279453677b49#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[AES_CMAC]`
- **Message:** _pytest.outcomes.XFailed: AES_CMAC sign with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CMAC sign with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F160 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:123d6235d1a2e9ee#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[AES_CTS]`
- **Message:** _pytest.outcomes.XFailed: AES_CTS sign with wrong key type: rejected with CKR_FUNCTION_FAILED, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTS sign with wrong key type: rejected with CKR_FUNCTION_FAILED, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F161 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5e131add0d8f4af7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[AES_MAC]`
- **Message:** _pytest.outcomes.XFailed: AES_MAC sign with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_MAC sign with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F162 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2339456441cbe8ff#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[DES3_CMAC]`
- **Message:** _pytest.outcomes.XFailed: DES3_CMAC sign with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CMAC sign with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F163 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:16f864cf29f39483#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[DES3_MAC]`
- **Message:** _pytest.outcomes.XFailed: DES3_MAC sign with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_MAC sign with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F164 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0603dd7a3abfaa25#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[SSL3_MD5_MAC]`
- **Message:** _pytest.outcomes.XFailed: SSL3_MD5_MAC sign with wrong key type: rejected with CKR_MECHANISM_PARAM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SSL3_MD5_MAC sign with wrong key type: rejected with CKR_MECHANISM_PARAM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F165 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e0a638e2f507c1aa#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[AES_CTS]`
- **Message:** _pytest.outcomes.XFailed: AES_CTS verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTS verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F166 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d37f35a8501d8a92#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[AES_MAC]`
- **Message:** _pytest.outcomes.XFailed: AES_MAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_MAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F167 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f2ae83c473cbee63#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[DES3_CMAC]`
- **Message:** _pytest.outcomes.XFailed: DES3_CMAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CMAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F168 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8346c36c5103c3c9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[DES3_MAC]`
- **Message:** _pytest.outcomes.XFailed: DES3_MAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_MAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F169 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:388c80bc95fa1bb0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[MD5_HMAC]`
- **Message:** _pytest.outcomes.XFailed: MD5_HMAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: MD5_HMAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F170 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:703ab86ef041e82c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[SSL3_MD5_MAC]`
- **Message:** _pytest.outcomes.XFailed: SSL3_MD5_MAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SSL3_MD5_MAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F171 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:085dad40193d911a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F172 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:401d5658ef69da73#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F173 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4fbcbe57430b4a73#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_CFB128]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB128 wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB128 wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F174 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8ed49877cd923628#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_CFB8]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB8 wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB8 wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F175 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:207316561fd890b0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F176 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:61d0e7cfe5485fb2#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F177 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:645bc5ac821be73b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_GCM]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_GCM wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F178 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:59fc4fd54f588268#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_KEY_WRAP]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_WRAP wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_WRAP wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F179 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f1f6e1474dadf31a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_OFB]`
- **Message:** _pytest.outcomes.XFailed: AES_OFB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_OFB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F180 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:365542a90772004e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_XTS]`
- **Message:** _pytest.outcomes.XFailed: AES_XTS wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_XTS wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F181 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:97b6d0dd511682ed#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES3_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F182 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:de759b5d1d25cc95#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES3_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F183 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:08dfc8b604fdc754#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES3_ECB]`
- **Message:** _pytest.outcomes.XFailed: DES3_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F184 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cca432dfd327f7ef#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F185 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6be8ee18bc2788c7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F186 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c319e57288b72bf6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES_CFB64]`
- **Message:** _pytest.outcomes.XFailed: DES_CFB64 wrap with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CFB64 wrap with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F187 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7a4162dbff7c4c5d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES_CFB8]`
- **Message:** _pytest.outcomes.XFailed: DES_CFB8 wrap with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CFB8 wrap with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F188 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:afe6cae8feace56e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES_ECB]`
- **Message:** _pytest.outcomes.XFailed: DES_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F189 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fbb9a733a9ff5a67#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES_OFB64]`
- **Message:** _pytest.outcomes.XFailed: DES_OFB64 wrap with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_OFB64 wrap with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F190 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9431826a4b4336c6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_malformed_required_param[EDDSA]`
- **Message:** _pytest.outcomes.XFailed: EDDSA C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: EDDSA C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F191 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:378ed1416dad3ccc#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[SHA1_KEY_DERIVATION]`
- **Message:** _pytest.outcomes.XFailed: SHA1_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA1_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F192 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1114aa924f6dd4c9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[SHA224_KEY_DERIVATION]`
- **Message:** _pytest.outcomes.XFailed: SHA224_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA224_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F193 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f201c04ffb1bfd73#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[SHA256_KEY_DERIVATION]`
- **Message:** _pytest.outcomes.XFailed: SHA256_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA256_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F194 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d96c5fb5e732073a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[SHA384_KEY_DERIVATION]`
- **Message:** _pytest.outcomes.XFailed: SHA384_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA384_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F195 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:59835aa1e1262f82#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[SHA512_224_KEY_DERIVATION]`
- **Message:** _pytest.outcomes.XFailed: SHA512_224_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_224_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F196 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:dea126f22889a536#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[SHA512_256_KEY_DERIVATION]`
- **Message:** _pytest.outcomes.XFailed: SHA512_256_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_256_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F197 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c59b7cd98cb06551#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[SHA512_KEY_DERIVATION]`
- **Message:** _pytest.outcomes.XFailed: SHA512_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_mech_sign.py` (2 findings)

#### F198 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3db76aceaaa77364`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[AES_CTS]`
- **Message:** _pytest.outcomes.XFailed: AES_CTS:sign: advertised but not operational (CKR_FUNCTION_FAILED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F199 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b1b1f3fdb758f1cf`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[HASH_ML_DSA]`
- **Message:** _pytest.outcomes.XFailed: HASH_ML_DSA:sign: advertised but not operational (CKR_FUNCTION_FAILED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_wrap.py` (4 findings)

#### F200 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:97f65584ae28d18b`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_wrap.py::TestMechWrapRoundtrip::test_wrap_unwrap_aes_key[AES_GCM]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM:wrap: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F201 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d0b01602ed8d4768`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_wrap.py::TestMechWrapRoundtrip::test_wrap_unwrap_aes_key[DES_CFB64]`
- **Message:** _pytest.outcomes.XFailed: DES_CFB64:wrap: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F202 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:da883f0fd7677d91`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_wrap.py::TestMechWrapRoundtrip::test_wrap_unwrap_aes_key[DES_CFB8]`
- **Message:** _pytest.outcomes.XFailed: DES_CFB8:wrap: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F203 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:df485899055d3c2a`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_wrap.py::TestMechWrapRoundtrip::test_wrap_unwrap_aes_key[DES_OFB64]`
- **Message:** _pytest.outcomes.XFailed: DES_OFB64:wrap: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_message_crypto.py` (1 findings)

#### F204 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:da7bf20bb2718302#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_single`
- **Message:** _pytest.outcomes.XFailed: advertised message encrypt rejected (CKM_AES_CBC): CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: advertised message encrypt rejected (CKM_AES_CBC): CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_operation_termination.py` (4 findings)

#### F205 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7952a463fd778028#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_c_verify_final_terminates_after_rejected_signature`
- **Message:** Failed: RSA: C_VerifyFinal(empty) returned CKR_ARGUMENTS_BAD but left the verify operation active (next C_VerifyInit -> CKR_OPERATION_ACTIVE) -- the spec requires C_VerifyFinal to ALWAYS terminate the active verification operation: success claimed then contradicted (self-contradiction)
- **Evidence:** C_VerifyFinal(empty sig) returned CKR_ARGUMENTS_BAD but left the verify operation active (next C_VerifyInit -> CKR_OPERATION_ACTIVE). PKCS#11 v3.1 requires C_VerifyFinal to ALWAYS terminate the active verification operation. lifecycle self-contradiction (claimed a verdict then didn't honor termination).

#### F206 [LOW/PROVIDER_BUG] — 📚 DOCS_ONLY
- **Signature:** `sha1:f568a84edcc8ebbc#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_c_encrypt_terminates_after_multipart[DES_CFB64]`
- **Message:** _pytest.outcomes.XFailed: DES_CFB64: multipart encrypt not operational: CKR_KEY_TYPE_INCONSISTENT
- **Evidence:** Advertised DES_CFB64 multipart encrypt rejects with CKR_KEY_TYPE_INCONSISTENT (not operational). Harness correctly xfails via xfail_if_known_ckr. Reject-valid on advertised mechanism - functional gap, not a security issue.

#### F207 [LOW/PROVIDER_BUG] — 📚 DOCS_ONLY
- **Signature:** `sha1:b3736946c404dd3e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_c_encrypt_terminates_after_multipart[DES_CFB8]`
- **Message:** _pytest.outcomes.XFailed: DES_CFB8: multipart encrypt not operational: CKR_KEY_TYPE_INCONSISTENT
- **Evidence:** Advertised DES_CFB8 multipart encrypt rejects with CKR_KEY_TYPE_INCONSISTENT (not operational). Harness correctly xfails via xfail_if_known_ckr. Reject-valid on advertised mechanism - functional gap, not a security issue.

#### F208 [LOW/PROVIDER_BUG] — 📚 DOCS_ONLY
- **Signature:** `sha1:e7c9b9fb3aad3667#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_c_encrypt_terminates_after_multipart[DES_OFB64]`
- **Message:** _pytest.outcomes.XFailed: DES_OFB64: multipart encrypt not operational: CKR_KEY_TYPE_INCONSISTENT
- **Evidence:** Advertised DES_OFB64 multipart encrypt rejects with CKR_KEY_TYPE_INCONSISTENT (not operational). Harness correctly xfails via xfail_if_known_ckr. Reject-valid on advertised mechanism - functional gap, not a security issue.

### `test_ro_session_restrictions.py` (1 findings)

#### F209 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3fe7442a1f9348c8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_ro_session_restrictions.py::TestROWrapUnwrapRestrictions::test_unwrap_to_token_object_in_ro_fails`
- **Message:** _pytest.outcomes.XFailed: C_UnwrapKey to TOKEN=True in RO session: rejected with CKR_TEMPLATE_INCOMPLETE, expected ['CKR_SESSION_READ_ONLY', 'CKR_ACTION_PROHIBITED', 'CKR_SESSION_READ_ONLY_EXISTS', 'CKR_TOKEN_WRITE_PROTECTED', 'CKR_ATTRIBUTE_READ_ONLY', 'CKR_FUNCTION_NOT_SUPPORTED', 'CKR_MECHANISM_I
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_UnwrapKey to TOKEN=True in RO session: rejected with CKR_TEMPLATE_INCOMPLETE, expected ['CKR_SESSION_READ_ONLY', 'CKR_ACTION_PROHIBITED', 'CKR_SESSION_READ_ONLY_EXISTS', 'CKR_TOKEN_WRITE_PROTECTED', 'CKR_ATTRIBUTE_READ_ONLY', 'CKR_FUNCTIO. Direction = reject-valid → functional gap (LOW).

### `test_sign_recover.py` (1 findings)

#### F210 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:ce9d71f57d9cd594`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_sign_recover.py::TestSignRecoverRecipes::test_verify_recover_invalid_signature`
- **Message:** _pytest.outcomes.XFailed: Module C_VerifyRecover accepted invalid all-zero signature: valid=True, recovered=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

### `test_ssl3.py` (1 findings)

#### F211 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:bda5a761720b2f65#phase6`
- **Direction:** `WRONG_OUTPUT` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_ssl3.py::TestSSL3KeyAndMacDerive::test_derive_key_material_exact_vector`
- **Message:** AssertionError: SSL3 key material output mismatch.
Actual:   698e3265825326fdf57444e2b1e45064cceb1267b84f81e14a1ce6c2d9696031f9efaf9d8e27955f638bda4d0df1d6ab0eca6dccabd29fdff201da989870bcea
Expected: 698e3265825326fdf57444e2b1e45064cceb1267b84f81e14a1ce6c2d9696031f9efaf9d8e27955f638bda4d0df1d6ab0eca
- **Evidence:** opencryptoki's CKM_SSL3_KEY_AND_MAC_DERIVE produces a correct 64-byte key block (client/server MAC secrets + client/server keys match RFC 6101 section 6.2.2 exactly) but omits the 32 bytes of client/server IV material the test requested: the 64-byte actual is a strict prefix of the 96-byte expected (test_ssl3.py:656-666). The underlying SSL3 PRF is correct; the gap is that the IV buffers are not populated. Functional gap on a legacy mechanism, not a crypto-correctness break.

### `test_v30_session.py` (1 findings)

#### F212 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:add42e008afebc53#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_v30_session.py::TestCLoginUser::test_c_login_user_empty_username_user_type`
- **Message:** _pytest.outcomes.XFailed: Module exposes C_LoginUser but returns a known unsupported/deviation CKR (expected CKR_OK or CKR_USER_ALREADY_LOGGED_IN per PKCS#11 v3.0 spec): CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: Module exposes C_LoginUser but returns a known unsupported/deviation CKR (expected CKR_OK or CKR_USER_ALREADY_LOGGED_IN per PKCS#11 v3.0 spec): CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_verify_signature.py` (1 findings)

#### F213 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:121ca620f06c5f18#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_verify_signature.py::TestVerifySignatureRoundtrip::test_verify_signature_multipart`
- **Message:** AssertionError: C_VerifySignatureUpdate failed with 0x00000070
assert <CKR_MECHANISM_INVALID: 0x00000070> == <CKR_OK: 0x00000000>
- **Evidence:** v3.0+ C_VerifySignatureInit succeeds (single-shot path works), but C_VerifySignatureUpdate returns CKR_MECHANISM_INVALID (0x70). The VerifySignature API is partially implemented: Init accepts the mechanism but the Update/Final multipart variant rejects it. Reject-valid on advertised v3.0 API - functional gap, not security.

### `test_wycheproof.py` (154 findings)

#### F214 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:eaa4396089c2db07#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc25-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc25 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc25-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F215 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:5de13ce80077f8f2#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc26-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc26 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc26-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F216 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:170da1dbf78cc0c6#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc27-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc27 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc27-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F217 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:dafe580c83160bb8#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc28-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc28 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc28-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F218 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:6255ada990832735#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc29-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc29 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc29-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F219 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:f811e3ab138d3e7a#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc30-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc30 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc30-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F220 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:56ff20b88b39eb4b#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc31-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc31 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc31-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F221 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:b2d3e28a11f8e3bd#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc32-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc32 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc32-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F222 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:8d89722d113f39ee#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc33-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc33 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc33-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F223 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:28348ae8471727ad#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc34-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc34 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc34-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F224 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:3fa45eedd4db5738#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc35-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc35 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc35-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F225 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:e2e5aeb73a10638d#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc36-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc36 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc36-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F226 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:8fc278c1f1f97239#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc37-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc37 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc37-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F227 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:8a08afdf85cdf3a6#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc38-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc38 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc38-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F228 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:a7ad991495c955e4#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc39-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc39 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc39-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F229 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:99b66fd298b23ed5#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc40-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc40 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc40-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F230 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:bba96a84518e8dd7#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc41-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc41 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc41-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F231 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:8696058789274528#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc42-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc42 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc42-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F232 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:020428df80df0b18#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc43-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc43 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc43-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F233 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:c003f0586aacd9ab#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc44-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc44 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc44-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F234 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:cd80d1d78a06e123#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc45-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc45 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc45-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F235 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:9dc19c570867f0bb#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc46-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc46 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc46-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F236 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:53028aa2848bdaf2#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc47-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc47 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc47-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F237 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:cc82bc8174a9e7cb#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc48-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc48 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc48-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F238 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:60f254defd7c4724#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc49-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc49 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc49-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F239 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:f66c9a5acae2da65#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc50-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc50 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc50-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F240 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:0fe5460453128c11#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc51-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc51 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc51-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F241 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:a33bdbe0f135e9d9#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc52-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc52 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc52-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F242 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:f3acfd534dbdc2bd#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc53-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc53 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc53-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F243 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:63f5cd722baaa3a8#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc54-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc54 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc54-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F244 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:cf43ca842530ca76#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc55-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc55 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc55-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F245 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:b5e8a0c671a90f18#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc56-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc56 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc56-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F246 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:cababbba248375a3#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc57-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc57 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc57-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F247 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:ffe575868c7cf239#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc58-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc58 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc58-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F248 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:7850b61a7ed51042#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc59-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc59 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc59-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F249 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:7b72a0edde72a887#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc60-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc60 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc60-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F250 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:2f6f01201c8f07bf#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc61-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc61 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc61-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F251 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:2aba820cbc35feef#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc62-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc62 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc62-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F252 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:6392623a8d838b62#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc63-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc63 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc63-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F253 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:ec8d32494ff2fdaf#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc64-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc64 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc64-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F254 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:e8d9fb891d68153e#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc65-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc65 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc65-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F255 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:9647b8b1a1790973#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc66-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc66 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc66-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F256 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:7a370430d094d982#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc67-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc67 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc67-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F257 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:4cbd8ce478868d31#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc68-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc68 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc68-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F258 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:c955da220846b365#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc69-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc69 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc69-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F259 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:4539907eba890c93#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc70-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc70 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc70-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F260 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:d34a5fce4ef4fc46#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc71-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc71 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc71-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F261 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:5ac9838b0e56f0ab#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc72-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc72 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc72-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F262 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:2e0ba02a0d42826c#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc97-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc97 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc97-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F263 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:07e7956f29d852dd#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc98-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc98 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc98-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F264 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:39666c65e85f52e1#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc99-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc99 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc99-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F265 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:68757ef0dc0c7d12#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc100-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc100 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc100-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F266 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:a24356e16b660565#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc101-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc101 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc101-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F267 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:ba7dcce6d2635228#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc102-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc102 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc102-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F268 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:5e14dda4a1f4468d#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc103-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc103 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc103-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F269 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:aaecf0db83a56b48#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc104-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc104 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc104-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F270 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:e9f9aa6e2276d31f#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc105-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc105 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc105-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F271 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:5667e1eda264833a#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc106-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc106 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc106-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F272 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:b93d2a067b2621c1#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc107-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc107 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc107-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F273 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:f9474eecde07a1d8#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc108-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc108 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc108-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F274 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:63ed5233f4ce4f56#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc109-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc109 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc109-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F275 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:517d472a5943a1d1#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc110-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc110 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc110-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F276 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:2b72e7b18ca6a41f#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc111-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc111 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc111-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F277 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:0d5e5002334d0a78#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc112-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc112 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc112-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F278 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:bbd98f9f6417517d#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc113-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc113 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc113-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F279 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:575050bf0d686a56#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc114-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc114 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc114-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F280 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:f8f7b1ee3bc3479e#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc115-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc115 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc115-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F281 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:2042e83cf0e3e9ca#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc116-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc116 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc116-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F282 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:de970055469e9f67#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc117-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc117 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc117-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F283 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:91a8767aee401787#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc118-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc118 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc118-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F284 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:14fe18ae96ef06de#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc119-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc119 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc119-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F285 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:c83e0881c710bd51#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc120-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc120 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc120-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F286 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:15d5dfacfbf697d8#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc121-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc121 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc121-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F287 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:70b02807ca580ecd#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc122-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc122 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc122-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F288 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:5851d92e770a187b#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc123-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc123 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc123-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F289 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:f07ad48031eb2fc2#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc124-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc124 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc124-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F290 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:d09d87c32abdca71#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc125-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc125 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc125-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F291 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:cf1ec12f42d46f78#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc126-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc126 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc126-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F292 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:5c926141bbefd47d#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc127-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc127 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc127-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F293 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:cedaa3e168a7cb65#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc128-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc128 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc128-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F294 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:594a91b7e5d86829#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc129-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc129 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc129-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F295 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:afb60abfbbb09d4e#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc130-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc130 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc130-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F296 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:6e68bca506042708#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc131-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc131 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc131-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F297 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:fb244c1608a76b80#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc132-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc132 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc132-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F298 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:43ee6532b0f7d5c6#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc133-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc133 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc133-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F299 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:407425bf547870e9#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc134-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc134 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc134-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F300 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:7c72975043064b6e#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc135-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc135 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc135-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F301 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:53015972549a15ed#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc136-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc136 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc136-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F302 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:e95711cff473c82e#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc137-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc137 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc137-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F303 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:55dbb128956f577d#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc138-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc138 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc138-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F304 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:f56373d50e286319#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc139-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc139 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc139-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F305 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:28bbe88d0c88bf94#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc140-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc140 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc140-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F306 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:65afead74af7b5a2#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc141-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc141 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc141-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F307 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:4022e7316e98f859#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc142-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc142 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc142-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F308 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:290eb72605307b29#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc143-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc143 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc143-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F309 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:d54e2b3931162b8b#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc144-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc144 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc144-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F310 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:d0c6712141e3050c#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc169-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc169 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc169-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F311 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:826ff4964b1d7c21#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc170-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc170 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc170-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F312 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:7358990bd2aed6a7#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc171-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc171 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc171-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F313 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:fdb5ce0d0d6279d8#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc172-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc172 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc172-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F314 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:f97e02fb47b6278d#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc173-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc173 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc173-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F315 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:bce10bb60d16aa45#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc174-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc174 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc174-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F316 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:2da8abb436e17f2e#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc175-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc175 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc175-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F317 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:bd0e95b7a0cfdb3f#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc176-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc176 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc176-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F318 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:30112aa0d9f93645#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc177-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc177 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc177-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F319 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:353830233d54d2a2#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc178-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc178 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc178-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F320 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:22a00450f7876c91#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc179-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc179 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc179-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F321 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:cf0b022108ccdf30#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc180-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc180 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc180-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F322 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:b5069872d1014d38#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc181-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc181 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc181-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F323 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:1f81bdb74b58b74a#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc182-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc182 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc182-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F324 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:8f5626ccbb8fcc61#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc183-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc183 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc183-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F325 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:5a6f5ee1bbcaa484#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc184-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc184 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc184-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F326 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:0e89b8f38be86fd2#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc185-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc185 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc185-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F327 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:a0a5f660d180f56d#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc186-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc186 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc186-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F328 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:58150db4232ff8c1#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc187-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc187 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc187-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F329 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:c0de0248ae1cb248#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc188-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc188 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc188-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F330 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:f3256cdffffa1413#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc189-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc189 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc189-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F331 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:f027edf2b56efe18#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc190-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc190 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc190-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F332 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:54f7ea4852a9e629#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc191-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc191 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc191-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F333 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:fe5adc88dd1c2c55#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc192-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc192 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc192-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F334 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:0cf4ac3a5af91e1f#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc193-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc193 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc193-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F335 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:874a01d969bf1039#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc194-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc194 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc194-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F336 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:78412732fea1d0ac#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc195-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc195 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc195-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F337 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:55d519fac44ab339#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc196-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc196 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc196-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F338 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:736a1d2890fea53b#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc197-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc197 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc197-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F339 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:c0de832bb8885cc9#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc198-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc198 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc198-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F340 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:d4030adec5d78624#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc199-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc199 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc199-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F341 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:f57f78fa536d998a#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc200-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc200 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc200-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F342 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:cba7119ebf6821d7#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc201-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc201 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc201-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F343 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:3f64641c0dfb7269#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc202-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc202 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc202-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F344 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:29fd5e8688f98d88#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc203-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc203 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc203-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F345 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:ff58723db2d13152#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc204-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc204 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc204-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F346 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:8476c369c41dbbab#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc205-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc205 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc205-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F347 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:a30caecaec788a18#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc206-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc206 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc206-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F348 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:02c998e111c36a65#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc207-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc207 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc207-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F349 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:5f32444b359380f4#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc208-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc208 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc208-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F350 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:48b5e5d54e6206ed#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc209-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc209 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc209-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F351 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:c167bc4afd319ed5#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc210-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc210 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc210-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F352 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:786746ada8dd2c05#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc211-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc211 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc211-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F353 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:89e415361befe64e#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc212-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc212 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc212-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F354 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:2d2eac39de5e9a5e#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc213-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc213 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc213-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F355 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:ae938fc602d57500#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc214-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc214 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc214-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F356 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:70bc2cf1e369314c#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc215-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc215 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc215-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F357 [HIGH/PROVIDER_BUG] — 🚨 USER_ESCALATION
- **Signature:** `sha1:8b261f332ce4f287#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc216-invalid]`
- **Message:** Failed: Invalid AES-CBC vector tc216 decrypted successfully
- **Evidence:** AES-CBC-PKCS5 padding oracle: invalid vector tc216-invalid with corrupted PKCS#5 padding DECRYPTED SUCCESSFULLY (CKR_OK) instead of being rejected with CKR_ENCRYPTED_DATA_INVALID / CKR_PADDING_ERROR. This is the Vaudenay active CBC plaintext-recovery oracle - an attacker can distinguish valid from invalid padding and iteratively recover plaintext. Cohort: 144 tcN-invalid vectors in opencryptoki-master all fail the same way (tc25..tc216). Same finding on opencryptoki (stable).

#### F358 [LOW/PROVIDER_BUG] — 📚 DOCS_ONLY
- **Signature:** `sha1:299a7fb1de409742#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP256Wycheproof::test_ecdsa_p256_sha256_verify[tc392-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc392: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** Invalid ECDSA signature (tc392-invalid) rejected with CKR_FUNCTION_FAILED instead of the spec-mandated CKR_SIGNATURE_INVALID. Reject-valid with non-clean CKR - harness correctly xfails via NON_CLEAN_SIGNATURE_REJECT_RVS. Cohort of 10 ECDSA tcN-invalid vectors on P-256/P-384 all reject with CKR_FUNCTION_FAILED. Functional/UX gap, the signature IS rejected (no forgery).

#### F359 [LOW/PROVIDER_BUG] — 📚 DOCS_ONLY
- **Signature:** `sha1:db6c319d4553c13d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP256Wycheproof::test_ecdsa_p256_sha256_verify[tc428-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc428: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** Invalid ECDSA signature (tc428-invalid) rejected with CKR_FUNCTION_FAILED instead of the spec-mandated CKR_SIGNATURE_INVALID. Reject-valid with non-clean CKR - harness correctly xfails via NON_CLEAN_SIGNATURE_REJECT_RVS. Cohort of 10 ECDSA tcN-invalid vectors on P-256/P-384 all reject with CKR_FUNCTION_FAILED. Functional/UX gap, the signature IS rejected (no forgery).

#### F360 [LOW/PROVIDER_BUG] — 📚 DOCS_ONLY
- **Signature:** `sha1:ff5fe0322e58425b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP256Wycheproof::test_ecdsa_p256_sha256_verify[tc431-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc431: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** Invalid ECDSA signature (tc431-invalid) rejected with CKR_FUNCTION_FAILED instead of the spec-mandated CKR_SIGNATURE_INVALID. Reject-valid with non-clean CKR - harness correctly xfails via NON_CLEAN_SIGNATURE_REJECT_RVS. Cohort of 10 ECDSA tcN-invalid vectors on P-256/P-384 all reject with CKR_FUNCTION_FAILED. Functional/UX gap, the signature IS rejected (no forgery).

#### F361 [LOW/PROVIDER_BUG] — 📚 DOCS_ONLY
- **Signature:** `sha1:7914712b3ebedd8a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP256Wycheproof::test_ecdsa_p256_sha256_verify[tc445-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc445: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** Invalid ECDSA signature (tc445-invalid) rejected with CKR_FUNCTION_FAILED instead of the spec-mandated CKR_SIGNATURE_INVALID. Reject-valid with non-clean CKR - harness correctly xfails via NON_CLEAN_SIGNATURE_REJECT_RVS. Cohort of 10 ECDSA tcN-invalid vectors on P-256/P-384 all reject with CKR_FUNCTION_FAILED. Functional/UX gap, the signature IS rejected (no forgery).

#### F362 [LOW/PROVIDER_BUG] — 📚 DOCS_ONLY
- **Signature:** `sha1:43bb2cc1b6f95cd3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP256Wycheproof::test_ecdsa_p256_sha256_verify[tc446-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc446: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** Invalid ECDSA signature (tc446-invalid) rejected with CKR_FUNCTION_FAILED instead of the spec-mandated CKR_SIGNATURE_INVALID. Reject-valid with non-clean CKR - harness correctly xfails via NON_CLEAN_SIGNATURE_REJECT_RVS. Cohort of 10 ECDSA tcN-invalid vectors on P-256/P-384 all reject with CKR_FUNCTION_FAILED. Functional/UX gap, the signature IS rejected (no forgery).

#### F363 [LOW/PROVIDER_BUG] — 📚 DOCS_ONLY
- **Signature:** `sha1:261ea4219a7eeb0b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP384Wycheproof::test_ecdsa_p384_sha384_verify[tc422-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc422: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** Invalid ECDSA signature (tc422-invalid) rejected with CKR_FUNCTION_FAILED instead of the spec-mandated CKR_SIGNATURE_INVALID. Reject-valid with non-clean CKR - harness correctly xfails via NON_CLEAN_SIGNATURE_REJECT_RVS. Cohort of 10 ECDSA tcN-invalid vectors on P-256/P-384 all reject with CKR_FUNCTION_FAILED. Functional/UX gap, the signature IS rejected (no forgery).

#### F364 [LOW/PROVIDER_BUG] — 📚 DOCS_ONLY
- **Signature:** `sha1:02bf7face671bbf1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP384Wycheproof::test_ecdsa_p384_sha384_verify[tc454-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc454: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** Invalid ECDSA signature (tc454-invalid) rejected with CKR_FUNCTION_FAILED instead of the spec-mandated CKR_SIGNATURE_INVALID. Reject-valid with non-clean CKR - harness correctly xfails via NON_CLEAN_SIGNATURE_REJECT_RVS. Cohort of 10 ECDSA tcN-invalid vectors on P-256/P-384 all reject with CKR_FUNCTION_FAILED. Functional/UX gap, the signature IS rejected (no forgery).

#### F365 [LOW/PROVIDER_BUG] — 📚 DOCS_ONLY
- **Signature:** `sha1:80a9e508711ff4d0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP384Wycheproof::test_ecdsa_p384_sha384_verify[tc457-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc457: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** Invalid ECDSA signature (tc457-invalid) rejected with CKR_FUNCTION_FAILED instead of the spec-mandated CKR_SIGNATURE_INVALID. Reject-valid with non-clean CKR - harness correctly xfails via NON_CLEAN_SIGNATURE_REJECT_RVS. Cohort of 10 ECDSA tcN-invalid vectors on P-256/P-384 all reject with CKR_FUNCTION_FAILED. Functional/UX gap, the signature IS rejected (no forgery).

#### F366 [LOW/PROVIDER_BUG] — 📚 DOCS_ONLY
- **Signature:** `sha1:5c7d5732639a5cf6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP384Wycheproof::test_ecdsa_p384_sha384_verify[tc471-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc471: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** Invalid ECDSA signature (tc471-invalid) rejected with CKR_FUNCTION_FAILED instead of the spec-mandated CKR_SIGNATURE_INVALID. Reject-valid with non-clean CKR - harness correctly xfails via NON_CLEAN_SIGNATURE_REJECT_RVS. Cohort of 10 ECDSA tcN-invalid vectors on P-256/P-384 all reject with CKR_FUNCTION_FAILED. Functional/UX gap, the signature IS rejected (no forgery).

#### F367 [LOW/PROVIDER_BUG] — 📚 DOCS_ONLY
- **Signature:** `sha1:b8d82aa01aa3dce7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP384Wycheproof::test_ecdsa_p384_sha384_verify[tc472-invalid]`
- **Message:** _pytest.outcomes.XFailed: tc472: signature verification rejected with non-clean CKR: CKR_FUNCTION_FAILED
- **Evidence:** Invalid ECDSA signature (tc472-invalid) rejected with CKR_FUNCTION_FAILED instead of the spec-mandated CKR_SIGNATURE_INVALID. Reject-valid with non-clean CKR - harness correctly xfails via NON_CLEAN_SIGNATURE_REJECT_RVS. Cohort of 10 ECDSA tcN-invalid vectors on P-256/P-384 all reject with CKR_FUNCTION_FAILED. Functional/UX gap, the signature IS rejected (no forgery).

### `test_wycheproof_aes.py` (81 findings)

#### F368 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:908501627396b934`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 41
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc27-valid]`
- **Message:** _pytest.outcomes.XFailed: AES_XTS:key-import: advertised but not operational (CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F369 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6fc1dea2bc4aa564#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc1-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc1-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F370 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:40e700d8ef16d673#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc2-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc2-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc2-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F371 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ad1dbd4929116ef0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc3-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc3-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc3-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F372 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a88e318916594031#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc4-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc4-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc4-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F373 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7acbf287fa864662#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc5-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc5-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc5-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F374 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a2d5dcb471807e96#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc6-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc6-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc6-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F375 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1b62609e9a347731#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc7-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc7-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc7-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F376 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a77e7935db6d6a94#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc8-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc8-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc8-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F377 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2cb3bf2fac536430#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc9-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc9-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc9-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F378 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e0ca1c9a1e861433#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc10-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc10-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc10-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F379 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:70793a7e7c7c3fcb#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc11-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc11-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc11-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F380 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:09f2736f529df5e3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc12-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc12-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc12-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F381 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c7a1d1db9d3cbe60#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc13-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc13-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc13-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F382 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4503177ccce4e733#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc14-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc14-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc14-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F383 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b5d164a602468e53#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc15-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc15-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc15-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F384 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:af154e2d296bdc46#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc16-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc16-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc16-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F385 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b457a1f77e9c8a9b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc17-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc17-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc17-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F386 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0660fdb236cf4def#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc18-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc18-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc18-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F387 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6b37cd0e79755231#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc19-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc19-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc19-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F388 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b57e267ac7ed60d1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc20-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc20-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc20-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F389 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:04f0f3b1530d3d88#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc21-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc21-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc21-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F390 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fd9e1fbcbaab6d2f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc22-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc22-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc22-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F391 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d52aabc26a5249a3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc23-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc23-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc23-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F392 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8f1f613b03acea88#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc24-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc24-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc24-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F393 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fa539d28e3e044b9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc25-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc25-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc25-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F394 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:52d04b0b17a80e70#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc26-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc26-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc26-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F395 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:03a21b58b8c18077#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc53-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc53-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc53-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F396 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:24116c20b0854826#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc54-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc54-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc54-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F397 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:99edbc368b9546eb#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc55-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc55-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc55-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F398 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d8563268109f7c73#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc56-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc56-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc56-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F399 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5935aae94e71ea64#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc57-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc57-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc57-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F400 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8b2d27663303e6a8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc58-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc58-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc58-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F401 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4ca5f800278902ec#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc59-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc59-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc59-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F402 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:972ae12d38eecc79#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc60-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc60-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc60-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F403 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d87bc3d61f510a61#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc61-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc61-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc61-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F404 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1ce20daf0228102c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc62-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc62-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc62-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F405 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:51262376e85824e8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc63-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc63-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc63-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F406 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0632ca7fc94d423a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc64-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc64-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc64-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F407 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1cae8688f53362e4#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc65-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc65-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc65-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F408 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4bee7cd6a1deab74#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc66-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc66-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc66-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F409 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:423569c8ad5da042#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc67-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc67-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc67-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F410 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9305baec93e8a846#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc68-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc68-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc68-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F411 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b8e3b35d1341d85a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc69-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc69-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc69-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F412 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:330ec52e7baa22ec#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc70-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc70-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc70-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F413 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5413b41a34c3fe6b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc71-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc71-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc71-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F414 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:910f74b9126da045#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc72-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc72-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc72-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F415 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a03ba497666a6e25#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc73-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc73-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc73-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F416 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c972394d9f9fb90b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc74-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc74-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc74-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F417 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:23cd643094841bdc#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc75-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc75-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc75-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F418 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:81beaa6923eba15b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc76-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc76-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc76-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F419 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9d5012cf6e4f9e54#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc77-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc77-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc77-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F420 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:769ad6902378f312#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc78-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc78-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc78-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F421 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:07d08f69cb2e160e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc79-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc79-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc79-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F422 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:eb8d36d82785bfa6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc81-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc81-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc81-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F423 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c26be02ba4ed4889#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc82-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc82-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc82-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F424 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9a5d76818f1c44dd#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc84-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc84-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc84-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F425 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:00cca6638e44a4b5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc85-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc85-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc85-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F426 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2184d02457341c12#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc87-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc87-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc87-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F427 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:112dcf6bb37d0d3b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc88-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc88-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc88-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F428 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1d4a64bff3d9878c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc90-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc90-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc90-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F429 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:301efcbfc0995bc0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc91-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc91-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc91-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F430 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:028ff55bd456e69c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc93-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc93-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc93-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F431 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b2faeef8f873c967#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc94-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc94-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc94-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F432 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cf66f00b04e1784e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc96-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc96-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc96-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F433 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d97b1bab4002c262#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc97-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc97-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc97-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F434 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:04966a709b1a4876#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc99-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc99-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc99-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F435 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a62d6ef16743531d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc100-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc100-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc100-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F436 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2c83566e626d5aa9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc102-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc102-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc102-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F437 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8b1ca4ea1cb729b1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc103-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc103-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc103-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F438 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3b09ca1bcfa956b9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc105-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc105-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc105-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F439 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:177d6987a1087065#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc106-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc106-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc106-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F440 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5706555eaa7eeda1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc108-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc108-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc108-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F441 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8611df9633956b5c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc109-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc109-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc109-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F442 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:51412e374fc99146#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc111-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc111-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc111-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F443 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4878b6b52e2555c6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc112-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc112-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc112-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F444 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f062588e2b7a82bf#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc114-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc114-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc114-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F445 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:667a062d6325b27f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc115-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc115-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc115-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F446 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:90db42e7ed4f3bd9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc117-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc117-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc117-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F447 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1be85befe9a239ba#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc118-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc118-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc118-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F448 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4ccdd36791192e77#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_xts[tc120-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-XTS tc120-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-XTS tc120-valid: advertised AES operation is not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_wycheproof_ecdsa.py` (1 findings)

#### F449 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c518bf8c62831d14`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1084
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py::test_ecdsa_wycheproof[ecdsa_secp160k1_sha256_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: ECDSA:key-import: advertised but not operational (secp160k1: CKR_FUNCTION_FAILED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_wycheproof_mldsa.py` (3 findings)

#### F450 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:93c0971761c0e5c5#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 9
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py::test_mldsa_verify[mldsa_44_verify_test.json:tc5-invalid]`
- **Message:** _pytest.outcomes.XFailed: mldsa_44_verify_test.json:tc5-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: mldsa_44_verify_test.json:tc5-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F451 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0182f83f37cf736a#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 9
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py::test_mldsa_verify[mldsa_65_verify_test.json:tc5-invalid]`
- **Message:** _pytest.outcomes.XFailed: mldsa_65_verify_test.json:tc5-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: mldsa_65_verify_test.json:tc5-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F452 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:931be9e71687f43a#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 9
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py::test_mldsa_verify[mldsa_87_verify_test.json:tc5-invalid]`
- **Message:** _pytest.outcomes.XFailed: mldsa_87_verify_test.json:tc5-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: mldsa_87_verify_test.json:tc5-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_wycheproof_rsa_oaep.py` (1 findings)

#### F453 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:16bf73bad3975fe4`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `xfail` · **Tests covered:** 26
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_oaep.py::test_rsa_oaep[rsa_oaep_2048_sha512_224_mgf1sha1_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: RSA-OAEP SHA-512/224/SHA-1 advertised but not operational (canonical OAEP SHA-512/224/SHA-1 decrypt rejected: Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK); vector: Unexpected CK_RV CKR_ENCRYPTED_DATA_INVALID; expected one of: CKR_OK
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_wycheproof_rsa_pss.py` (3 findings)

#### F454 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1422d6ed4741aadc#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 195
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py::test_rsa_pss[rsa_pss_2048_sha256_mgf1sha1_20_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: rsa_pss_2048_sha256_mgf1sha1_20_test.json:tc1-valid: advertised RSA-PSS parameters are not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: rsa_pss_2048_sha256_mgf1sha1_20_test.json:tc1-valid: advertised RSA-PSS parameters are not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F455 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e9f814db4856e83b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 120
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py::test_rsa_pss[rsa_pss_misc_params_test.json:tc7-valid]`
- **Message:** _pytest.outcomes.XFailed: rsa_pss_misc_params_test.json:tc7-valid: advertised RSA-PSS parameters are not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: rsa_pss_misc_params_test.json:tc7-valid: advertised RSA-PSS parameters are not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F456 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2eb53c6a3b7da1a6#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 91
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py::test_rsa_pss[rsa_pss_2048_sha256_mgf1sha1_20_test.json:tc62-invalid]`
- **Message:** _pytest.outcomes.XFailed: rsa_pss_2048_sha256_mgf1sha1_20_test.json:tc62-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: rsa_pss_2048_sha256_mgf1sha1_20_test.json:tc62-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).


## Already documented in `docs/module-issues.md` (5 findings)

These records match an existing module-issues.md entry. Not re-listed here to avoid duplication; see `verdicts.jsonl` for individual pointers.

## Not yet classified (83 groups, DEFERRED)

Per user directive m0213-m0214, classification extension stopped. These will be classified by an in-tool workflow.

Top by size:
| Group size | Direction | Test file | Signature |
|---:|---|---|---|
| 45 | REJECT_VALID | `test_wycheproof_ecdsa.py` | `sha1:f3d8ee9cbf3add0e` |
| 35 | REJECT_VALID | `test_wycheproof_ecdsa.py` | `sha1:760afb32337c2d4c` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:b2a9be5a284a392c` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:41bc24a909d7f386` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:8fbc0d80a2e770aa` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:84edff85fc98bfba` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:9f8da8a1f6ec78c7` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:99c71969a53c0a67` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:20f399a65bab4700` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:7bb423595fdbbd7b` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:6668eb5621e3812f` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:feadb08ca54f67fd` |
| 31 | REJECT_VALID | `test_wycheproof_ecdsa.py` | `sha1:610851b409d800d3` |
| 30 | REJECT_VALID | `test_wycheproof_ecdsa.py` | `sha1:faa80b9129b2ca75` |
| 25 | REJECT_VALID | `test_wycheproof_ecdsa.py` | `sha1:18fdbe1ac3610822` |
