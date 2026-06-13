# softhsm2-main — Per-Failure Triage

**Effective records:** 185
**Categories:** {'PROVIDER_BUG': 78, 'UNKNOWN': 42, 'SOFT_TOKEN_CAVEAT': 35, 'KNOWN_ISSUE': 29, 'SPEC_AMBIGUITY': 1}
**Severities:** {'LOW': 77, 'MEDIUM': 73, 'INFO': 27, 'HIGH': 8}

## Findings (114)

Ordered by severity then category.

### `test_acvp_eddsa.py` (4 findings)

#### F001 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:b6e0cff1882820a8`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::TestEdDsaKeyVer::test_eddsa_keyver[EDDSA-KeyVer-ED-25519-tc1]`
- **Message:** Failed: EDDSA-KeyVer-ED-25519-tc1: Module ACCEPTED an INVALID EdDSA key
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F002 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:c2f6334322814adc`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::TestEdDsaKeyVer::test_eddsa_keyver[EDDSA-KeyVer-ED-25519-tc4]`
- **Message:** Failed: EDDSA-KeyVer-ED-25519-tc4: Module ACCEPTED an INVALID EdDSA key
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F003 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:2026a3b78dd283c9`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::TestEdDsaKeyVer::test_eddsa_keyver[EDDSA-KeyVer-ED-448-tc6]`
- **Message:** Failed: EDDSA-KeyVer-ED-448-tc6: Module ACCEPTED an INVALID EdDSA key
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F004 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:a9de53e3b782361a`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::TestEdDsaKeyVer::test_eddsa_keyver[EDDSA-KeyVer-ED-448-tc8]`
- **Message:** Failed: EDDSA-KeyVer-ED-448-tc8: Module ACCEPTED an INVALID EdDSA key
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

### `test_acvp_mldsa.py` (1 findings)

#### F005 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f3b89b5235e42499#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 44
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py::TestMlDsaSigGen::test_mldsa_siggen[ML-DSA-sigGen-ML-DSA-44-tc17]`
- **Message:** _pytest.outcomes.XFailed: ML-DSA-sigGen-ML-DSA-44-tc17: signature generation: advertised ML-DSA operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ML-DSA-sigGen-ML-DSA-44-tc17: signature generation: advertised ML-DSA operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_ckr_decrypt.py` (1 findings)

#### F006 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:15d2a71e790a23a9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_decrypt.py::TestDecryptInitErrors::test_mechanism_param_invalid`
- **Message:** _pytest.outcomes.XFailed: C_DecryptInit(wrong_mechanism_parameter): rejected with CKR_MECHANISM_INVALID, spec prefers ['CKR_MECHANISM_PARAM_INVALID'] [PKCS#11 v3.1 Sec.5.9.1]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_DecryptInit(wrong_mechanism_parameter): rejected with CKR_MECHANISM_INVALID, spec prefers ['CKR_MECHANISM_PARAM_INVALID'] [PKCS#11 v3.1 Sec.5.9.1]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_derive.py` (1 findings)

#### F007 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:76b037851fca1472#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_derive.py::TestDeriveKeyErrors::test_key_type_inconsistent`
- **Message:** _pytest.outcomes.XFailed: C_DeriveKey(base_key_type_wrong_for_mechanism): rejected with CKR_TEMPLATE_INCOMPLETE, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.14.5]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_DeriveKey(base_key_type_wrong_for_mechanism): rejected with CKR_TEMPLATE_INCOMPLETE, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.14.5]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_encrypt.py` (1 findings)

#### F008 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ee8a18cf9ca1f919#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_encrypt.py::TestEncryptInitErrors::test_mechanism_param_invalid`
- **Message:** _pytest.outcomes.XFailed: C_EncryptInit(wrong_mechanism_parameter): rejected with CKR_MECHANISM_INVALID, spec prefers ['CKR_MECHANISM_PARAM_INVALID'] [PKCS#11 v3.1 Sec.5.8.1]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_EncryptInit(wrong_mechanism_parameter): rejected with CKR_MECHANISM_INVALID, spec prefers ['CKR_MECHANISM_PARAM_INVALID'] [PKCS#11 v3.1 Sec.5.8.1]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_raw_buffer.py` (2 findings)

#### F009 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:af93fb2d100df5fd#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestBufferTooSmall::test_digest_buffer_too_small`
- **Message:** _pytest.outcomes.XFailed: C_Digest returned CKR_OK for a 1-byte output buffer without writing past it (PKCS#11 §5.10.2 expects CKR_BUFFER_TOO_SMALL; clean return-code deviation, no buffer overflow)
- **Evidence:** Buffer-protocol deviation: C_Digest returned CKR_OK for a 1-byte output buffer without writing past it (PKCS#11 §5.10.2 expects CKR_BUFFER_TOO_SMALL; clean return-code deviation, no buffer overflow).

#### F010 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c8ef0faee47128bf#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestByteOutputBufferTooSmallGuards::test_get_operation_state_buffer_too_small_preserves_guard`
- **Message:** _pytest.outcomes.XFailed: C_GetOperationState is not saveable: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_GetOperationState is not saveable: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_ckr_sign.py` (1 findings)

#### F011 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a9c2ab3728e434d0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_sign.py::TestSignInitErrors::test_mechanism_param_invalid`
- **Message:** _pytest.outcomes.XFailed: C_SignInit(wrong_mechanism_parameter): rejected with CKR_ARGUMENTS_BAD, spec prefers ['CKR_MECHANISM_PARAM_INVALID'] [PKCS#11 v3.1 Sec.5.10.1]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_SignInit(wrong_mechanism_parameter): rejected with CKR_ARGUMENTS_BAD, spec prefers ['CKR_MECHANISM_PARAM_INVALID'] [PKCS#11 v3.1 Sec.5.10.1]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_wrap.py` (2 findings)

#### F012 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2cb7f89cff1a9025#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_wrap.py::TestWrapKeyErrors::test_wrapping_key_size_range`
- **Message:** _pytest.outcomes.XFailed: C_WrapKey(wrapping_key_size_out_of_range): rejected with CKR_GENERAL_ERROR, spec prefers ['CKR_WRAPPING_KEY_SIZE_RANGE', 'CKR_KEY_SIZE_RANGE', 'CKR_WRAPPING_KEY_TYPE_INCONSISTENT', 'CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.14.3]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_WrapKey(wrapping_key_size_out_of_range): rejected with CKR_GENERAL_ERROR, spec prefers ['CKR_WRAPPING_KEY_SIZE_RANGE', 'CKR_KEY_SIZE_RANGE', 'CKR_WRAPPING_KEY_TYPE_INCONSISTENT', 'CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.14.3]. Direction = reject-valid → functional gap (LOW).

#### F013 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f43a3b6e41c045aa#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_wrap.py::TestUnwrapKeyErrors::test_unwrap_token_bool_overlong_length`
- **Message:** _pytest.outcomes.XFailed: C_UnwrapKey with CK_ULONG-sized CKA_TOKEN boolean attribute: rejected with CKR_ATTRIBUTE_READ_ONLY, expected ['CKR_ATTRIBUTE_TYPE_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONSISTENT', 'CKR_ARGUMENTS_BAD', 'CKR_FUNCTION_FAILED']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_UnwrapKey with CK_ULONG-sized CKA_TOKEN boolean attribute: rejected with CKR_ATTRIBUTE_READ_ONLY, expected ['CKR_ATTRIBUTE_TYPE_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONSISTENT', 'CKR_ARGUMENT. Direction = reject-valid → functional gap (LOW).

### `test_api_security.py` (1 findings)

#### F014 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ec775855fc5a2c9b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_api_security.py::TestWrapDecryptOracle::test_wrap_decrypt_combination_prevented`
- **Message:** _pytest.outcomes.XFailed: API security wrap-decrypt operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: API security wrap-decrypt operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_arithmetic_overflow.py` (10 findings)

#### F015 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:bdd248bba1512ce1`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestTemplateCountOverflow::test_template_count_overflow[create_object-ulong_max]`
- **Message:** Failed: C_CreateObject(template_count=0x100000000): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F016 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:b46459d3446ef120`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestTemplateCountOverflowValidHandles::test_template_count_overflow_with_valid_object_handle[get_attribute_value-ulong_max]`
- **Message:** Failed: C_GetAttributeValue(valid object, template_count=0x100000000): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F017 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:ca6a43ca3797cf4c`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestTemplateCountOverflowValidHandles::test_template_count_overflow_with_valid_object_handle[copy_object-ulong_max]`
- **Message:** Failed: C_CopyObject(valid object, template_count=0x100000000): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F018 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:732fc2589341f407`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestDeriveTemplateCountOverflowValidBase::test_derive_key_template_count_overflow_with_valid_base_key[ulong_max]`
- **Message:** Failed: C_DeriveKey(valid base, template_count=0x100000000): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F019 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:32ff236a42811c0b`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestMechanismParamLengthOverflow::test_mechanism_param_length_overflow[aes_cbc]`
- **Message:** Failed: C_EncryptInit(CKM_AES_CBC, pParameter=16B, ulParameterLen=0xffffffffffffffff): subprocess failed with exit code 5
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F020 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:1aec6849cd52f0fe`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestTemplateCountOverflow::test_template_count_overflow[generate_key-ulong_max]`
- **Message:** Failed: C_GenerateKey(template_count=0xffffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F021 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:792ceaa845344452`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestTemplateCountOverflow::test_template_count_overflow[generate_key-sizeof_attr_overflow]`
- **Message:** Failed: C_GenerateKey(template_count=0xaaaaaaaaaaaaaab): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F022 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:4a081b0d4279b42d`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestTemplateCountOverflow::test_template_count_overflow[generate_key-0x100000000]`
- **Message:** Failed: C_GenerateKey(template_count=0x100000000): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F023 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:bf056f464d656450`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestGenerateKeyPairCountOverflow::test_generate_key_pair_count_overflow[pub_template_overflow]`
- **Message:** Failed: C_GenerateKeyPair(pub_count=0xffffffffffffffff, priv_count=0x1): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F024 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:2263ae3b0218f5d3`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestGenerateKeyPairCountOverflow::test_generate_key_pair_count_overflow[priv_template_overflow]`
- **Message:** Failed: C_GenerateKeyPair(pub_count=0x1, priv_count=0xffffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_ffi_length_boundary.py` (21 findings)

#### F025 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:9dfb2ad144693976`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_sign_isize_boundary[isize_max]`
- **Message:** Failed: C_Sign(HMAC_SHA256, ulDataLen=0x7fffffffffffffff): subprocess failed with exit code 5
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F026 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:0818c9fb66d6a670`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_verify_isize_data_len[isize_max]`
- **Message:** Failed: C_Verify(HMAC_SHA256, ulDataLen=0x7fffffffffffffff): subprocess failed with exit code 5
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F027 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:77dbc875301f2245`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_digest_isize_boundary[isize_max]`
- **Message:** Failed: C_Digest(SHA256, ulDataLen=0x7fffffffffffffff): subprocess failed with exit code 5
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F028 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:14f917277f4ddde8`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_digest_isize_boundary[isize_max_plus_1]`
- **Message:** Failed: C_Digest(SHA256, ulDataLen=0x8000000000000000): subprocess failed with exit code 5
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F029 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:5ef1c61d904564cc`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[encrypt_update-isize_max_plus_1]`
- **Message:** Failed: C_EncryptUpdate(ulDataLen=0x8000000000000000): subprocess failed with exit code 5
stdout: TARGET:C_EncryptUpdate
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F030 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:122d54175d588a2c`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[decrypt_update-isize_max_plus_1]`
- **Message:** Failed: C_DecryptUpdate(ulDataLen=0x8000000000000000): subprocess failed with exit code 5
stdout: TARGET:C_DecryptUpdate
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F031 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:59b85d0d51919ebd`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[sign_update-isize_max]`
- **Message:** Failed: C_SignUpdate(ulDataLen=0x7fffffffffffffff): subprocess failed with exit code 5
stdout: TARGET:C_SignUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F032 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:248bd908355d2ded`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[sign_update-isize_max_plus_1]`
- **Message:** Failed: C_SignUpdate(ulDataLen=0x8000000000000000): subprocess failed with exit code 5
stdout: TARGET:C_SignUpdate
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F033 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:3b994b756d2d486d`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[verify_update-isize_max]`
- **Message:** Failed: C_VerifyUpdate(ulDataLen=0x7fffffffffffffff): subprocess failed with exit code 5
stdout: TARGET:C_VerifyUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F034 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:5ca499f94e7e222c`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[verify_update-isize_max_plus_1]`
- **Message:** Failed: C_VerifyUpdate(ulDataLen=0x8000000000000000): subprocess failed with exit code 5
stdout: TARGET:C_VerifyUpdate
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F035 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:a9f50aa1e080cf6e`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[digest_update-isize_max]`
- **Message:** Failed: C_DigestUpdate(ulDataLen=0x7fffffffffffffff): subprocess failed with exit code 5
stdout: TARGET:C_DigestUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F036 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:e458a1e9ce892b4d`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[digest_update-isize_max_plus_1]`
- **Message:** Failed: C_DigestUpdate(ulDataLen=0x8000000000000000): subprocess failed with exit code 5
stdout: TARGET:C_DigestUpdate
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F037 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:539520875455c41c`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRandomIsizeLength::test_generate_random_isize_length_preserves_guard[isize_max]`
- **Message:** Failed: C_GenerateRandom(ulRandomLen=0x7fffffffffffffff): subprocess failed with exit code 5
stdout: TARGET:C_GenerateRandom
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F038 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:efc8466afbb14228`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRandomIsizeLength::test_generate_random_isize_length_preserves_guard[isize_max_plus_1]`
- **Message:** Failed: C_GenerateRandom(ulRandomLen=0x8000000000000000): subprocess failed with exit code 5
stdout: TARGET:C_GenerateRandom
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F039 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:034e560a5672160d`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRandomIsizeLength::test_seed_random_isize_length_rejects_cleanly[isize_max]`
- **Message:** Failed: C_SeedRandom(ulSeedLen=0x7fffffffffffffff): subprocess failed with exit code 5
stdout: TARGET:C_SeedRandom
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F040 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:2319109417fa5136`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRandomIsizeLength::test_seed_random_isize_length_rejects_cleanly[isize_max_plus_1]`
- **Message:** Failed: C_SeedRandom(ulSeedLen=0x8000000000000000): subprocess failed with exit code 5
stdout: TARGET:C_SeedRandom
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F041 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:736db61b618cee43`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestMechanismNullInnerParams::test_gcm_null_iv`
- **Message:** Failed: C_EncryptInit(AES_GCM, pIv=NULL, ulIvLen=12): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F042 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:9b9ac32da78da5c2`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestAesCbcEncryptDataMalformedParams::test_aes_cbc_encrypt_data_malformed_params[tiny_data_huge_length]`
- **Message:** Failed: C_DeriveKey(AES_CBC_ENCRYPT_DATA, pData=tiny,length=isize_max_plus_1): subprocess failed with exit code 5
stdout: TARGET_CALL:C_DeriveKey(AES_CBC_ENCRYPT_DATA,pData=tiny,length=isize_max_plus_1)
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F043 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:7e7fe8602522b07f`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestGcmAadLengthBoundary::test_gcm_aad_length_boundary[isize_max]`
- **Message:** Failed: C_Encrypt(AES_GCM, ulAADLen=0x7fffffffffffffff): subprocess failed with exit code 5
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F044 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:ea49808054124bd6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestGcmAadLengthBoundary::test_gcm_aad_length_boundary[isize_max_plus_1]`
- **Message:** Failed: C_Encrypt(AES_GCM, ulAADLen=0x8000000000000000): subprocess failed with exit code 5
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F045 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:a6b272bfe7c3d3ce`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRsaPssSaltLengthBoundary::test_rsa_pss_salt_length_boundary[isize_max]`
- **Message:** _pytest.outcomes.XFailed: C_Sign(SHA256_RSA_PKCS_PSS, sLen=0x7fffffffffffffff): rejected with CKR_MECHANISM_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_DATA_LEN_RANGE', 'CKR_KEY_SIZE_RANGE', 'CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCON
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_parameter_validation.py` (2 findings)

#### F046 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:023cfb9a740b7728#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestRsaExponent::test_rsa_weak_public_exponent[e=0]`
- **Message:** _pytest.outcomes.XFailed: RSA keygen with cryptographically invalid exponent e=0: rejected with CKR_GENERAL_ERROR, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RSA keygen with cryptographically invalid exponent e=0: rejected with CKR_GENERAL_ERROR, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_. Direction = reject-valid → functional gap (LOW).

#### F047 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:dd9551e6036280dd#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestEcPointValidation::test_ecdh_invalid_point[off-curve-point]`
- **Message:** _pytest.outcomes.XFailed: ECDH derive with infinity EC public point (invalid-curve attack): rejected with CKR_GENERAL_ERROR, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ECDH derive with infinity EC public point (invalid-curve attack): rejected with CKR_GENERAL_ERROR, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR. Direction = reject-valid → functional gap (LOW).

### `test_recover_length_boundary.py` (2 findings)

#### F048 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c279951f15634731#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_recover_length_boundary.py::TestRecoverInputLengthBoundary::test_sign_recover_huge_data_len_does_not_crash[isize_max]`
- **Message:** _pytest.outcomes.XFailed: C_SignRecoverInit rejected: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_SignRecoverInit rejected: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F049 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:efda67014dd27bc1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_recover_length_boundary.py::TestRecoverInputLengthBoundary::test_verify_recover_huge_signature_len_does_not_crash[isize_max]`
- **Message:** _pytest.outcomes.XFailed: C_VerifyRecoverInit rejected: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_VerifyRecoverInit rejected: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_secret_key_value_len.py` (1 findings)

#### F050 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5b158d1ce40ce783#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestUnwrapSecretKeyValueLen::test_aes_ecb_unwrap_oversized_value_len_does_not_crash`
- **Message:** _pytest.outcomes.XFailed: AES-ECB key wrap setup rejected: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-ECB key wrap setup rejected: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_errors.py` (2 findings)

#### F051 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:14a72139a38dde52`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_errors.py::TestInvalidOperations::test_invalid_mechanism_param`
- **Message:** _pytest.outcomes.XFailed: C_EncryptInit with an undersized AES-CBC-PAD IV: rejected with CKR_MECHANISM_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

#### F052 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ef74706afc294f16`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_errors.py::TestEmptyInputs::test_encrypt_empty_data`
- **Message:** _pytest.outcomes.XFailed: C_Encrypt (length query) of empty data under AES-CBC-PAD: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_DATA_LEN_RANGE']
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

### `test_mech_derive.py` (2 findings)

#### F053 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:76729de1fe681035`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_derive.py::TestMechDerive::test_derive_produces_key[DES3_ECB_ENCRYPT_DATA]`
- **Message:** _pytest.outcomes.XFailed: DES3_ECB_ENCRYPT_DATA:derive: advertised but not operational (CKR_FUNCTION_FAILED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F054 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:69f6f323777f6413`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_derive.py::TestMechDerive::test_derive_produces_key[DES_ECB_ENCRYPT_DATA]`
- **Message:** _pytest.outcomes.XFailed: DES_ECB_ENCRYPT_DATA:derive: advertised but not operational (CKR_FUNCTION_FAILED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_multipart.py` (7 findings)

#### F055 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1c055ac115819889`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[ECDSA_SHA1]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA1:multipart-sign: advertised but not operational (CKR_OPERATION_NOT_INITIALIZED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F056 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:caee6000909f1415`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[ECDSA_SHA224]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA224:multipart-sign: advertised but not operational (CKR_OPERATION_NOT_INITIALIZED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F057 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:160100f5aee128a3`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[ECDSA_SHA256]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA256:multipart-sign: advertised but not operational (CKR_OPERATION_NOT_INITIALIZED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F058 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3caaa86c9fed2e2d`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[ECDSA_SHA384]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA384:multipart-sign: advertised but not operational (CKR_OPERATION_NOT_INITIALIZED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F059 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:929263482501119c`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[ECDSA_SHA512]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA512:multipart-sign: advertised but not operational (CKR_OPERATION_NOT_INITIALIZED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F060 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:61630381eb4f6df3`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[EDDSA]`
- **Message:** _pytest.outcomes.XFailed: EDDSA:multipart-sign: advertised but not operational (CKR_OPERATION_NOT_INITIALIZED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F061 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:97a3ce7b5674b990`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[ML_DSA]`
- **Message:** _pytest.outcomes.XFailed: ML_DSA:multipart-verify: advertised but not operational (CKR_OPERATION_NOT_INITIALIZED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_negative.py` (47 findings)

#### F062 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:542a38d13a357f18#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F063 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ae5b6de682c4c877#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F064 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8208da7d4ec899c3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES3_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F065 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b151b762bba949f5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F066 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b145cb97d897e7f8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 7
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_derive_wrong_key_type[CONCATENATE_BASE_AND_KEY]`
- **Message:** _pytest.outcomes.XFailed: CONCATENATE_BASE_AND_DATA keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CONCATENATE_BASE_AND_DATA keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F067 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5b7525d94e902380#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_KEY_WRAP]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_WRAP keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_WRAP keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F068 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a34bbaf2cfbf68d7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_KEY_WRAP_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_WRAP_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_WRAP_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F069 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f3355f8c209de770#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC_PAD C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F070 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e9c1858ef42cf3af#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[DES3_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC_PAD C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC_PAD C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F071 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:72bd518bbec5a7e0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[DES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC_PAD C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC_PAD C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F072 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9b86ff971a4f3159#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F073 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:53df809f4a61c940#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA1_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA1_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA1_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F074 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ec4832864f406cc7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA224_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA224_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA224_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F075 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c69bfcdc47ec5da5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA256_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA256_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA256_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F076 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6b41efb39298c6d8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA384_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA384_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA384_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F077 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ea4222968d068aca#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA512_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA512_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F078 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0e57c90cf6dc9a67#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_derive_missing_required_param[CONCATENATE_DATA_AND_BASE]`
- **Message:** _pytest.outcomes.XFailed: CONCATENATE_DATA_AND_BASE keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CONCATENATE_DATA_AND_BASE keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F079 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:11d464a37a667a28#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_MECHANISM_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_MECHANISM_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F080 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c9e4ec3adaf77262#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[DES3_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_MECHANISM_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_MECHANISM_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F081 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:dc37c61ba3938e1f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[DES_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_MECHANISM_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_MECHANISM_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F082 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:90c7d7b3e2cbe57b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[RSA_PKCS_OAEP]`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_OAEP C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RSA_PKCS_OAEP C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F083 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:edd674d4760dfef9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_MECHANISM_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_MECHANISM_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F084 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:aa8326aef634b1df#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[DES3_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_MECHANISM_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_MECHANISM_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F085 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:bdaf1fe5b9c93e58#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[DES_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_MECHANISM_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_MECHANISM_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F086 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:555ebb6ee6a81981#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F087 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:09b7e66f0e7b19a0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F088 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fd9d64c319d1541a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[AES_GCM]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_GCM keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F089 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:81c06a8b96009b18#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[DES3_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F090 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8b3c1d3d5a5df15e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[DES3_ECB]`
- **Message:** _pytest.outcomes.XFailed: DES3_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F091 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5bb35b813a80088f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[DES_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F092 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9334bc56661d376b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[DES_ECB]`
- **Message:** _pytest.outcomes.XFailed: DES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F093 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0563d9b940b3b009#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[AES_CMAC]`
- **Message:** _pytest.outcomes.XFailed: AES_CMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F094 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1a5f7cba5c6fa20d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[DES3_CMAC]`
- **Message:** _pytest.outcomes.XFailed: DES3_CMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F095 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cc43d5799cff603a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[MD5_HMAC]`
- **Message:** _pytest.outcomes.XFailed: MD5_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: MD5_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F096 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:28cb3a5f247e48dd#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA224_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA224_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA224_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F097 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d5f008d0c1e18f4e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA256_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA256_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F098 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4df8caac188ac172#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA384_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA384_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA384_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F099 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d4ea01ee50ae069b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA512_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA512_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F100 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fa8dd5f3fcc2a05a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA_1_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA_1_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA_1_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F101 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:83039ba1cac06acd#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES3_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC_PAD wrap with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC_PAD wrap with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F102 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d8d479ddb29af4ac#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC_PAD wrap with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC_PAD wrap with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F103 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:19c33bdff4530d21#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F104 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f5764173222c5d9e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_GCM]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_GCM C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F105 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:89ee1c4ecba0581f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F106 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:57af72d4e22827d0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_GCM]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_GCM C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F107 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4fc02f175b125ec8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_malformed_required_param[EDDSA]`
- **Message:** _pytest.outcomes.XFailed: EDDSA C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: EDDSA C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F108 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:55a741aa892a8413#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[AES_ECB_ENCRYPT_DATA]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB_ENCRYPT_DATA keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_ECB_ENCRYPT_DATA keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_mech_wrap.py` (2 findings)

#### F109 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:de44b0bcaf7eaa68`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_wrap.py::TestMechWrapRoundtrip::test_wrap_unwrap_aes_key[DES3_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC_PAD:wrap: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F110 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b0c4d5cc946b512b`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_wrap.py::TestMechWrapRoundtrip::test_wrap_unwrap_aes_key[DES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC_PAD:wrap: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_remaining_gaps.py` (1 findings)

#### F111 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:685db398f790f686#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_remaining_gaps.py::TestTemplateConstraintAttributes::test_wrap_template_enforces_target_attributes`
- **Message:** _pytest.outcomes.XFailed: CKM_AES_KEY_WRAP advertised but matching-template unwrap is not operational: CKR_ATTRIBUTE_READ_ONLY
- **Evidence:** Capability gap: CKM_AES_KEY_WRAP advertised but matching-template unwrap is not operational: CKR_ATTRIBUTE_READ_ONLY. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_ro_session_restrictions.py` (1 findings)

#### F112 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:df4506e6e0d44014#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_ro_session_restrictions.py::TestROWrapUnwrapRestrictions::test_unwrap_to_token_object_in_ro_fails`
- **Message:** _pytest.outcomes.XFailed: C_UnwrapKey to TOKEN=True in RO session: rejected with CKR_TEMPLATE_INCOMPLETE, expected ['CKR_SESSION_READ_ONLY', 'CKR_ACTION_PROHIBITED', 'CKR_SESSION_READ_ONLY_EXISTS', 'CKR_TOKEN_WRITE_PROTECTED', 'CKR_ATTRIBUTE_READ_ONLY', 'CKR_FUNCTION_NOT_SUPPORTED', 'CKR_MECHANISM_I
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_UnwrapKey to TOKEN=True in RO session: rejected with CKR_TEMPLATE_INCOMPLETE, expected ['CKR_SESSION_READ_ONLY', 'CKR_ACTION_PROHIBITED', 'CKR_SESSION_READ_ONLY_EXISTS', 'CKR_TOKEN_WRITE_PROTECTED', 'CKR_ATTRIBUTE_READ_ONLY', 'CKR_FUNCTIO. Direction = reject-valid → functional gap (LOW).

### `test_set_attribute.py` (1 findings)

#### F113 [LOW/SPEC_AMBIGUITY] — 🔍 MANUAL_REVIEW
- **Signature:** `sha1:df0e9ce3df8c296c#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_set_attribute.py::TestSetAttributeAtomicity::test_set_attribute_mixed_template_is_atomic`
- **Message:** Failed: C_SetAttributeValue partially applied CKA_LABEL before rejecting a later read-only CKA_CLASS row
- **Evidence:** softhsm2-main C_SetAttributeValue with a mixed mutable(read-only) template partially applies CKA_LABEL then rejects the later read-only CKA_CLASS row (test_set_attribute.py:204). Read-only CKA_CLASS was NOT actually changed. PKCS#11 v3.1 Sec.5.7 does not explicitly mandate atomicity for C_SetAttributeValue, and the same partial-application pattern reproduces across several providers (bouncyhsm, kryptic) -> spec-ambiguous atomicity expectation, not a security break.

### `test_wycheproof_x25519.py` (1 findings)

#### F114 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:68cfe26e022458ac`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1017
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_x25519.py::test_xdh[x25519_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: ECDH:Montgomery-private-import: advertised but not operational (CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.


## Already documented in `docs/module-issues.md` (29 findings)

These records match an existing module-issues.md entry. Not re-listed here to avoid duplication; see `verdicts.jsonl` for individual pointers.

## Not yet classified (42 groups, DEFERRED)

Per user directive m0213-m0214, classification extension stopped. These will be classified by an in-tool workflow.

Top by size:
| Group size | Direction | Test file | Signature |
|---:|---|---|---|
| 33 | CLEAN_ERROR | `test_acvp_hmac.py` | `sha1:e6ff99fba8567c85` |
| 31 | CLEAN_ERROR | `test_acvp_hmac.py` | `sha1:06bac0f8bec21107` |
| 30 | CLEAN_ERROR | `test_acvp_hmac.py` | `sha1:0ea8eb55fef0bf2e` |
| 30 | OTHER | `test_wycheproof_hmac.py` | `sha1:65b76d9a92334085` |
| 30 | OTHER | `test_wycheproof_hmac.py` | `sha1:3c2c0a1a2282ad2a` |
| 30 | OTHER | `test_wycheproof_hmac.py` | `sha1:8de6f0f1e8024361` |
| 30 | OTHER | `test_wycheproof_hmac.py` | `sha1:ad28932ba2bdeccc` |
| 27 | CLEAN_ERROR | `test_acvp_hmac.py` | `sha1:784f283f76e4a299` |
| 15 | CLEAN_ERROR | `test_wycheproof_ecdh.py` | `sha1:4683026d21026e5a` |
| 14 | CLEAN_ERROR | `test_wycheproof_ecdh.py` | `sha1:e05e52005b8c2545` |
| 6 | CLEAN_ERROR | `test_wycheproof.py` | `sha1:cab581d4a6de5b4c` |
| 6 | CLEAN_ERROR | `test_wycheproof_hmac.py` | `sha1:e982fd2dc4254ec9` |
| 6 | CLEAN_ERROR | `test_wycheproof_hmac.py` | `sha1:e9ee462a396853ec` |
| 6 | CLEAN_ERROR | `test_wycheproof_hmac.py` | `sha1:77b0aec0868e0dde` |
| 6 | CLEAN_ERROR | `test_wycheproof_hmac.py` | `sha1:411482ecfbf25f5f` |
