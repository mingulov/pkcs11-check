# kryoptic-main — Per-Failure Triage

**Effective records:** 807
**Categories:** {'KNOWN_ISSUE': 526, 'PROVIDER_BUG': 181, 'SOFT_TOKEN_CAVEAT': 65, 'UNKNOWN': 35}
**Severities:** {'INFO': 524, 'LOW': 153, 'MEDIUM': 71, 'HIGH': 58, 'CRITICAL': 1}

## Findings (246)

Ordered by severity then category.

### `test_acvp_eddsa.py` (4 findings)

#### F001 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:639d61e9d2099297`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::TestEdDsaKeyVer::test_eddsa_keyver[EDDSA-KeyVer-ED-25519-tc1]`
- **Message:** Failed: EDDSA-KeyVer-ED-25519-tc1: Module ACCEPTED an INVALID EdDSA key
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F002 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:50774b3e64f572b0`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::TestEdDsaKeyVer::test_eddsa_keyver[EDDSA-KeyVer-ED-25519-tc4]`
- **Message:** Failed: EDDSA-KeyVer-ED-25519-tc4: Module ACCEPTED an INVALID EdDSA key
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F003 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:3fb97c09e74d3483`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::TestEdDsaKeyVer::test_eddsa_keyver[EDDSA-KeyVer-ED-448-tc6]`
- **Message:** Failed: EDDSA-KeyVer-ED-448-tc6: Module ACCEPTED an INVALID EdDSA key
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F004 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:13f7784e7491e54d`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::TestEdDsaKeyVer::test_eddsa_keyver[EDDSA-KeyVer-ED-448-tc8]`
- **Message:** Failed: EDDSA-KeyVer-ED-448-tc8: Module ACCEPTED an INVALID EdDSA key
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

### `test_acvp_mldsa.py` (1 findings)

#### F005 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:37163512b56004ee#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 13
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_mldsa.py::TestMlDsaSigGen::test_mldsa_siggen[ML-DSA-sigGen-ML-DSA-44-tc17]`
- **Message:** _pytest.outcomes.XFailed: ML-DSA-sigGen-ML-DSA-44-tc17: signature generation: advertised ML-DSA operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ML-DSA-sigGen-ML-DSA-44-tc17: signature generation: advertised ML-DSA operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_ckr_decrypt.py` (5 findings)

#### F006 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:06d6e9e0d43eec23#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_decrypt.py::TestDecryptDataErrors::test_rsa_ciphertext_wrong_length`
- **Message:** Failed: C_Decrypt(RSA_ciphertext_wrong_length): accepted (CKR_OK) but must reject [PKCS#11 v3.1 Sec.5.9.2]
- **Evidence:** kryoptic-main accepts (CKR_OK) a 128-byte ciphertext on C_Decrypt(CKM_RSA_PKCS) with an RSA-2048 key (expects 256). test_ckr_decrypt.py:157 explicitly classifies this as Type-A accept-invalid on RSA-PAD. Per triage model, accept-invalid on RSA-PAD -> HIGH (oracle/padding surface). Smoking gun: rv==CKR_OK on wrong-length RSA ciphertext.

#### F007 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7a919ab3dd52f301#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 5
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_decrypt.py::TestDecryptDataErrors::test_ecb_ciphertext_not_aligned[1]`
- **Message:** _pytest.outcomes.XFailed: C_Decrypt(ciphertext_not_block_aligned): rejected with CKR_DATA_LEN_RANGE, spec prefers ['CKR_ENCRYPTED_DATA_LEN_RANGE'] [PKCS#11 v3.1 Sec.5.9.2]
- **Evidence:** kryptic-main C_Decrypt on not-block-aligned ECB/CBC ciphertext returns CKR_DATA_LEN_RANGE; spec prefers CKR_ENCRYPTED_DATA_LEN_RANGE (5 parametrized cases). Clean CKR-code deviation, no security impact; the input IS rejected.

#### F008 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d05681821fd35e08#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_decrypt.py::TestDecryptInitErrors::test_mechanism_param_invalid`
- **Message:** _pytest.outcomes.XFailed: C_DecryptInit(wrong_mechanism_parameter): rejected with CKR_ARGUMENTS_BAD, spec prefers ['CKR_MECHANISM_PARAM_INVALID'] [PKCS#11 v3.1 Sec.5.9.1]
- **Evidence:** kryptic-main C_DecryptInit with a wrong mechanism parameter returns CKR_ARGUMENTS_BAD; spec prefers CKR_MECHANISM_PARAM_INVALID. Clean CKR deviation; init is rejected.

#### F009 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4f63541505f654d4#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_decrypt.py::TestDecryptDataErrors::test_rsa_oaep_garbage`
- **Message:** _pytest.outcomes.XFailed: C_Decrypt(RSA_OAEP_garbage_ciphertext): rejected with CKR_DEVICE_ERROR, spec prefers ['CKR_ENCRYPTED_DATA_INVALID'] [PKCS#11 v3.1 Sec.5.9.2]
- **Evidence:** kryptic-main C_Decrypt(CKM_RSA_PKCS_OAEP) on garbage 256-byte ciphertext returns CKR_DEVICE_ERROR; spec prefers CKR_ENCRYPTED_DATA_INVALID. Clean reject with a broad code; no oracle since input is refused.

#### F010 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4cea00f326c95247#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_decrypt.py::TestDecryptDataErrors::test_key_handle_invalid`
- **Message:** _pytest.outcomes.XFailed: C_DecryptInit(invalid_key_handle): rejected with CKR_OBJECT_HANDLE_INVALID, spec prefers ['CKR_KEY_HANDLE_INVALID'] [PKCS#11 v3.1 Sec.5.9.1]
- **Evidence:** kryptic-main C_DecryptInit with a destroyed key handle returns CKR_OBJECT_HANDLE_INVALID; spec prefers CKR_KEY_HANDLE_INVALID. Clean CKR naming deviation (handle no longer resolves to any object).

### `test_ckr_derive.py` (1 findings)

#### F011 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:40fd4c20bbe37e95#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_derive.py::TestDeriveKeyErrors::test_key_type_inconsistent`
- **Message:** _pytest.outcomes.XFailed: C_DeriveKey(base_key_type_wrong_for_mechanism): rejected with CKR_ARGUMENTS_BAD, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.14.5]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_DeriveKey(base_key_type_wrong_for_mechanism): rejected with CKR_ARGUMENTS_BAD, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.14.5]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_encrypt.py` (1 findings)

#### F012 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d236e5a650449abf#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_encrypt.py::TestEncryptInitErrors::test_mechanism_param_invalid`
- **Message:** _pytest.outcomes.XFailed: C_EncryptInit(wrong_mechanism_parameter): rejected with CKR_ARGUMENTS_BAD, spec prefers ['CKR_MECHANISM_PARAM_INVALID'] [PKCS#11 v3.1 Sec.5.8.1]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_EncryptInit(wrong_mechanism_parameter): rejected with CKR_ARGUMENTS_BAD, spec prefers ['CKR_MECHANISM_PARAM_INVALID'] [PKCS#11 v3.1 Sec.5.8.1]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_kem.py` (2 findings)

#### F013 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ec21f7753dbc7bb5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_kem.py::TestEncapsulateKeyErrors::test_mechanism_invalid`
- **Message:** _pytest.outcomes.XFailed: C_EncapsulateKey(RSA_key_with_ML_KEM_mechanism): rejected with CKR_TEMPLATE_INCONSISTENT, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.2 Sec.5.14.7]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_EncapsulateKey(RSA_key_with_ML_KEM_mechanism): rejected with CKR_TEMPLATE_INCONSISTENT, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.2 Sec.5.14.7]. Direction = reject-valid → functional gap (LOW).

#### F014 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:30d7e19180156243#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_kem.py::TestDecapsulateKeyErrors::test_mechanism_invalid`
- **Message:** _pytest.outcomes.XFailed: C_DecapsulateKey(garbage_ciphertext): rejected with CKR_TEMPLATE_INCONSISTENT, spec prefers ['CKR_ENCRYPTED_DATA_INVALID'] [PKCS#11 v3.2 Sec.5.14.8]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_DecapsulateKey(garbage_ciphertext): rejected with CKR_TEMPLATE_INCONSISTENT, spec prefers ['CKR_ENCRYPTED_DATA_INVALID'] [PKCS#11 v3.2 Sec.5.14.8]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_keygen.py` (1 findings)

#### F015 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:55b8cc8d9a3717a0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyPairErrors::test_attribute_type_invalid`
- **Message:** _pytest.outcomes.XFailed: C_GenerateKey(bogus_attribute_in_template): rejected with CKR_ATTRIBUTE_VALUE_INVALID, spec prefers ['CKR_ATTRIBUTE_TYPE_INVALID'] [PKCS#11 v3.1 Sec.5.14.1]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_GenerateKey(bogus_attribute_in_template): rejected with CKR_ATTRIBUTE_VALUE_INVALID, spec prefers ['CKR_ATTRIBUTE_TYPE_INVALID'] [PKCS#11 v3.1 Sec.5.14.1]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_object.py` (1 findings)

#### F016 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:dc4ef445fa0d38fd#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_object.py::TestSetAttributeErrors::test_set_readonly_class`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_GENERAL_ERROR; expected one of: CKR_OK, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID
- **Evidence:** kryoptic's C_SetAttributeValue on a CKO_DATA object accepts a read-only CKA_CLASS write to CKO_SECRET_KEY (returns CKR_OK), then read_attributes -> C_GetAttributeValue returns CKR_GENERAL_ERROR (test_ckr_object.py:352-356). Object left in a broken state after an accepted write -> Type C self-contradiction. Same root class as the kryoptic test_set_attribute.py failures.

### `test_ckr_raw_buffer.py` (9 findings)

#### F017 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8ac8b1be5f5c17a2`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestDecryptBufferTooSmallGuards::test_aes_cbc_pad_decrypt_buffer_too_small_preserves_guard_and_retries`
- **Message:** Failed: C_Decrypt AES-CBC-PAD undersized output buffer guard: subprocess failed with exit code 1
stdout: CKR:0x00000150
LEN:1
OVERWRITTEN:0
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

#### F018 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:69cbece15d07e786#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestListBufferTooSmallGuards::test_get_mechanism_list_buffer_too_small_preserves_guard`
- **Message:** Failed: C_GetMechanismList undersized list buffer guard: subprocess failed with exit code 1
stdout: CKR:0x00000150
LEN:1
OVERWRITTEN:0
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"
- **Evidence:** kryptic-main C_GetMechanismList with a 1-entry buffer returns CKR_BUFFER_TOO_SMALL (0x150, correct) and does not overwrite the guard (OVERWRITTEN:0, correct) BUT leaves pulCount=1 instead of setting it to the required total. Spec (v3.1 Sec.5.5) requires *pulCount to hold the needed count on CKR_BUFFER_TOO_SMALL; callers cannot size the retry buffer. test_ckr_raw_buffer.py buffer-guard subprocess.

#### F019 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3c6e7a7e8d228bda#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestListBufferTooSmallGuards::test_get_interface_list_buffer_too_small_preserves_guard`
- **Message:** Failed: C_GetInterfaceList undersized list buffer guard: subprocess failed with exit code 1
stdout: CKR:0x00000150
LEN:1
OVERWRITTEN:0
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"
- **Evidence:** kryptic-main C_GetInterfaceList with a 1-entry buffer returns CKR_BUFFER_TOO_SMALL but leaves pulCount=1 (same shape as the C_GetMechanismList finding). Spec requires *pulCount = needed total on CKR_BUFFER_TOO_SMALL. test_ckr_raw_buffer.py buffer-guard subprocess.

#### F020 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e5c974f7f0de6bc1#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestByteOutputBufferTooSmallGuards::test_wrap_key_buffer_too_small_preserves_guard`
- **Message:** AssertionError: C_WrapKey reported required length 1, expected 24
assert 1 == 24
- **Evidence:** kryptic-main C_WrapKey with an undersized output buffer reports required length 1, expected 24 (assert 1 == 24). Wrong required-length on the CKR_BUFFER_TOO_SMALL path -> two-call sizing is broken for wrap. test_ckr_raw_buffer.py TestByteOutputBufferTooSmallGuards.

#### F021 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e3fc0842f76fec88#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestDecryptBufferTooSmallGuards::test_aes_cbc_pad_encrypt_final_buffer_too_small_preserves_guard_and_retries`
- **Message:** _pytest.outcomes.XFailed: C_EncryptFinal returned CKR_BUFFER_TOO_SMALL but did not report a usable retry length
- **Evidence:** kryptic-main C_EncryptFinal returns CKR_BUFFER_TOO_SMALL but does not report a usable retry length (same class as the other buffer-sizing findings). Callers cannot recover the required output size. test_ckr_raw_buffer.py xfail.

#### F022 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3cead37f6b487acc#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestDecryptBufferTooSmallGuards::test_aes_cbc_pad_decrypt_update_buffer_too_small_preserves_guard_and_retries`
- **Message:** _pytest.outcomes.XFailed: C_DecryptUpdate failed: CKR_BUFFER_TOO_SMALL
- **Evidence:** kryptic-main multipart AES-CBC-PAD decrypt-update buffer-too-small retry path: C_DecryptUpdate raised CKR_BUFFER_TOO_SMALL during the guard/retry probe (2 cases). Buffer-sizing deviation in the multipart decrypt-update retry; input not silently accepted.

#### F023 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2ef15f5d875f9ad4#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestBufferTooSmall::test_digest_buffer_too_small`
- **Message:** _pytest.outcomes.XFailed: C_Digest returned CKR_OK for a 1-byte output buffer without writing past it (PKCS#11 §5.10.2 expects CKR_BUFFER_TOO_SMALL; clean return-code deviation, no buffer overflow)
- **Evidence:** kryptic-main C_Digest with a 1-byte output buffer returns CKR_OK (without overflowing the guard) instead of CKR_BUFFER_TOO_SMALL. Clean return-code deviation, no buffer overflow (guard intact); spec v3.1 Sec.5.10.2 wants CKR_BUFFER_TOO_SMALL.

#### F024 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:604f7ca5d0618f17#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestByteOutputBufferTooSmallGuards::test_get_operation_state_buffer_too_small_preserves_guard`
- **Message:** _pytest.outcomes.XFailed: C_GetOperationState with a one-byte output buffer: rejected with CKR_GENERAL_ERROR, expected ['CKR_BUFFER_TOO_SMALL']
- **Evidence:** kryptic-main C_GetOperationState with a 1-byte output buffer returns CKR_GENERAL_ERROR; spec prefers CKR_BUFFER_TOO_SMALL. Clean CKR deviation on the buffer-too-small path.

#### F025 [LOW/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:5bedc4253989569d#phase6`
- **Direction:** `OTHER` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestListBufferTooSmallGuards::test_get_slot_list_buffer_too_small_preserves_guard`
- **Message:** _pytest.outcomes.XFailed: C_GetSlotList returned only 1 slot(s)
- **Evidence:** kryptic-main exposes only 1 slot, so test_get_slot_list_buffer_too_small_preserves_guard cannot trigger CKR_BUFFER_TOO_SMALL (a 1-entry buffer suffices). Soft-token shape, not a conformance defect; the buffer-guard assertion is untestable on a single-slot token.

### `test_ckr_sign.py` (1 findings)

#### F026 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:129cdf216ba02b17#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_sign.py::TestSignInitErrors::test_mechanism_param_invalid`
- **Message:** _pytest.outcomes.XFailed: C_SignInit(wrong_mechanism_parameter): rejected with CKR_ARGUMENTS_BAD, spec prefers ['CKR_MECHANISM_PARAM_INVALID'] [PKCS#11 v3.1 Sec.5.10.1]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_SignInit(wrong_mechanism_parameter): rejected with CKR_ARGUMENTS_BAD, spec prefers ['CKR_MECHANISM_PARAM_INVALID'] [PKCS#11 v3.1 Sec.5.10.1]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_spec_compliance.py` (1 findings)

#### F027 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fccacc2958e42be0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_spec_compliance.py::TestCKRTemplateCompliance::test_invalid_class_returns_attribute_value_invalid`
- **Message:** _pytest.outcomes.XFailed: C_CreateObject(bad CLASS): rejected with CKR_TEMPLATE_INCONSISTENT, expected ['CKR_ATTRIBUTE_VALUE_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_CreateObject(bad CLASS): rejected with CKR_TEMPLATE_INCONSISTENT, expected ['CKR_ATTRIBUTE_VALUE_INVALID']. Direction = reject-valid → functional gap (LOW).

### `test_api_boundary.py` (1 findings)

#### F028 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:9a3c6d14f595b1d2`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_api_boundary.py::TestGenerateAesExtremeKeySize::test_generate_aes_extreme_key_size`
- **Message:** Failed: C_GenerateKey(CKA_VALUE_LEN=0xffffffffffffffff): module crashed with signal 6
stdout: 
stderr: thread '<unnamed>' (157) panicked at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/alloc/src/raw_vec/mod.rs:28:5:
capacity overflow
note: run with `RUST_BACKTRACE=1` environment variable
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_arithmetic_overflow.py` (6 findings)

#### F029 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:e97a982a29583f85`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestTemplateCountOverflow::test_template_count_overflow[find_objects_init-ulong_max]`
- **Message:** Failed: C_FindObjectsInit(template_count=0x100000000): module crashed with signal 6
stdout: 
stderr: memory allocation of 274877906944 bytes failed
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F030 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:995b640e80e1884d`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestTemplateCountOverflowValidHandles::test_template_count_overflow_with_valid_object_handle[get_attribute_value-ulong_max]`
- **Message:** Failed: C_GetAttributeValue(valid object, template_count=0x100000000): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F031 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:3aead6261498d83d`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestKemTemplateCountOverflow::test_kem_output_template_count_overflow[decapsulate_key-ulong_max]`
- **Message:** Failed: C_DecapsulateKey(ML-KEM output template_count=0x100000000): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F032 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:d26d23e287371427`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestKemTemplateCountOverflow::test_kem_output_template_count_overflow[encapsulate_key-sizeof_attr_overflow]`
- **Message:** Failed: C_EncapsulateKey(ML-KEM output template_count=0x100000000): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F033 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:63576b0cc24da7be`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestDeriveTemplateCountOverflowValidBase::test_derive_key_template_count_overflow_with_valid_base_key[ulong_max]`
- **Message:** Failed: C_DeriveKey(valid base, template_count=0xffffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F034 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:5ddfe5a6dcf10957`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestKeyValueLenOverflow::test_key_value_len_overflow[aes]`
- **Message:** Failed: C_GenerateKey(CKM_AES_KEY_GEN, CKA_VALUE_LEN=0xffffffffffffffff): module crashed with signal 6
stdout: 
stderr: thread '<unnamed>' (209) panicked at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/alloc/src/raw_vec/mod.rs:28:5:
capacity overflow
note: run with `RUST_BACKTRACE=1` envi
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_ffi_length_boundary.py` (21 findings)

#### F035 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:00858e1806430cc4`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 5
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestSp800108NullDataParams::test_sp800_108_null_data_params`
- **Message:** Failed: C_DeriveKey(SP800_108_COUNTER_KDF, data-param count=0x7fffffffffffffff): module crashed with signal 6
stdout: 
stderr: thread '<unnamed>' (303) panicked at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/alloc/src/raw_vec/mod.rs:28:5:
capacity overflow
note: run with `RUST_BACKTRACE=
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F036 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:5ef81d82920c85af`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_sign_isize_boundary[isize_max]`
- **Message:** Failed: C_Sign(HMAC_SHA256, ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F037 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:e70b939db0850388`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_verify_isize_data_len[isize_max]`
- **Message:** Failed: C_Verify(HMAC_SHA256, ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F038 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:cde5ac5100780897`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestPbkdf2NestedLengthBoundary::test_pbkdf2_nested_length_boundary[password-isize_max]`
- **Message:** Failed: C_GenerateKey(PBKDF2, password length=0x7fffffffffffffff): module crashed with signal 6
stdout: 
stderr: memory allocation of 9223372036854775807 bytes failed
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F039 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:73779bd55b37c95e`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestPbkdf2NestedLengthBoundary::test_pbkdf2_nested_length_boundary[salt-isize_max]`
- **Message:** Failed: C_GenerateKey(PBKDF2, salt length=0x7fffffffffffffff): module crashed with signal 6
stdout: 
stderr: memory allocation of 9223372036854775807 bytes failed
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F040 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:824bfc8d32e98f92`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestTlsKdfRandomLengthBoundary::test_tls_kdf_random_length_boundary[client_random-isize_max]`
- **Message:** Failed: C_DeriveKey(TLS_KDF, client random length=0x7fffffffffffffff): module crashed with signal 6
stdout: 
stderr: memory allocation of 9223372036854775807 bytes failed
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F041 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:1495e4286bd51aca`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestTlsKdfRandomLengthBoundary::test_tls_kdf_random_length_boundary[server_random-isize_max]`
- **Message:** Failed: C_DeriveKey(TLS_KDF, server random length=0x7fffffffffffffff): module crashed with signal 6
stdout: 
stderr: memory allocation of 9223372036854775807 bytes failed
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F042 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:9baf1078c35a6c43`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_digest_isize_boundary[isize_max]`
- **Message:** Failed: C_Digest(SHA256, ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F043 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:7950c7ef570d1d54`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_digest_isize_boundary[isize_max_plus_1]`
- **Message:** Failed: C_Digest(SHA256, ulDataLen=0x8000000000000000): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F044 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:3c8fd0956d111ab1`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[sign_update-isize_max]`
- **Message:** Failed: C_SignUpdate(ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_SignUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F045 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:8cb1795bdc1b506a`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[sign_update-isize_max_plus_1]`
- **Message:** Failed: C_SignUpdate(ulDataLen=0x8000000000000000): module crashed with signal 11
stdout: TARGET:C_SignUpdate
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F046 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:a3b3d8f2fbd31016`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[verify_update-isize_max]`
- **Message:** Failed: C_VerifyUpdate(ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_VerifyUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F047 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:3f7f3b714eb15a6f`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[verify_update-isize_max_plus_1]`
- **Message:** Failed: C_VerifyUpdate(ulDataLen=0x8000000000000000): module crashed with signal 11
stdout: TARGET:C_VerifyUpdate
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F048 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:fc440db7e066633c`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[digest_update-isize_max]`
- **Message:** Failed: C_DigestUpdate(ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_DigestUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F049 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:34ca86f6d3ed90c7`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[digest_update-isize_max_plus_1]`
- **Message:** Failed: C_DigestUpdate(ulDataLen=0x8000000000000000): module crashed with signal 11
stdout: TARGET:C_DigestUpdate
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F050 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:19be38ee61095876`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRandomIsizeLength::test_generate_random_isize_length_preserves_guard[isize_max]`
- **Message:** Failed: C_GenerateRandom(ulRandomLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_GenerateRandom
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F051 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:16c5624bd64767da`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRandomIsizeLength::test_generate_random_isize_length_preserves_guard[isize_max_plus_1]`
- **Message:** Failed: C_GenerateRandom(ulRandomLen=0x8000000000000000): module crashed with signal 11
stdout: TARGET:C_GenerateRandom
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F052 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:427ff0ae9ca9c38c`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestAllocationGuard::test_generate_key_oom_value_len`
- **Message:** subprocess.TimeoutExpired: Command '['/app/.venv/bin/python', '-c', 'import atexit as _atexit\nimport json as _json\nimport os as _os\nfrom pkcs11_check.raw.api import RawPKCS11\nfrom pkcs11_check.raw.bootstrap import (\n    close_session_quietly, get_slot_ids, login_user, open_session,\n)\nfrom pkc
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F053 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:40f79d7545c723b2`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestAesCbcEncryptDataMalformedParams::test_aes_cbc_encrypt_data_malformed_params[tiny_data_huge_length]`
- **Message:** Failed: C_DeriveKey(AES_CBC_ENCRYPT_DATA, pData=tiny,length=isize_max_plus_1): module crashed with signal 6
stdout: TARGET_CALL:C_DeriveKey(AES_CBC_ENCRYPT_DATA,pData=tiny,length=isize_max_plus_1)
stderr: thread '<unnamed>' (284) panicked at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/al
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F054 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:3449fe1ba16b808b`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestTlsKdfNullParams::test_tls_kdf_null_label`
- **Message:** Failed: C_DeriveKey(TLS_KDF, pLabel=NULL, ulLabelLength=16): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F055 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:886bb7ec1dd51c95`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRsaPssSaltLengthBoundary::test_rsa_pss_salt_length_boundary[isize_max]`
- **Message:** _pytest.outcomes.XFailed: C_Sign(SHA256_RSA_PKCS_PSS, sLen=0x7fffffffffffffff): rejected with CKR_GENERAL_ERROR, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_DATA_LEN_RANGE', 'CKR_KEY_SIZE_RANGE', 'CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONSIST
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_ffi_null_pointer.py` (3 findings)

#### F056 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b2ed1595109a0f66#phase6`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestNullRandomBuffer::test_generate_random_null_buffer`
- **Message:** Failed: C_GenerateRandom(buf=NULL, buf_len=32): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** C_GenerateRandom(buf=NULL, buf_len=32) crashes signal 11. PKCS#11 section 2.3.3 requires CKR_ARGUMENTS_BAD for NULL pointer with nonzero length. Not documented in module-issues.md for kryptic C_GenerateRandom.

#### F057 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a300b263485f5a97#phase6`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestNullOperationState::test_set_operation_state_null_buffer`
- **Message:** Failed: C_SetOperationState(state=NULL, state_len=32): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** C_SetOperationState(state=NULL, state_len=32) crashes signal 11. PKCS#11 section 2.3.3 requires CKR_ARGUMENTS_BAD for NULL pointer with nonzero length. Not documented in module-issues.md for kryptic C_SetOperationState.

#### F058 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1f48de11c63e0623#phase6`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestHmacGeneralNullParam::test_hmac_general_null_parameter`
- **Message:** Failed: C_SignInit(CKM_SHA256_HMAC_GENERAL, pParameter=NULL, ulParameterLen=8): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** C_SignInit(CKM_SHA256_HMAC_GENERAL, pParameter=NULL, ulParameterLen=8) crashes signal 11. HMAC-GENERAL requires a CK_ULONG MAC-length parameter; NULL pParameter with nonzero length must yield CKR_ARGUMENTS_BAD. Not documented in module-issues.md.

### `test_parameter_validation.py` (2 findings)

#### F059 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f900da9e476dc76f#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestRsaExponent::test_rsa_weak_public_exponent[e=0]`
- **Message:** _pytest.outcomes.XFailed: RSA keygen with cryptographically invalid exponent e=0: rejected with CKR_DEVICE_ERROR, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RSA keygen with cryptographically invalid exponent e=0: rejected with CKR_DEVICE_ERROR, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_I. Direction = reject-valid → functional gap (LOW).

#### F060 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:92693be0ed194083#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestEcPointValidation::test_ecdh_invalid_point[off-curve-point]`
- **Message:** _pytest.outcomes.XFailed: ECDH derive with infinity EC public point (invalid-curve attack): rejected with CKR_KEY_INDIGESTIBLE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ECDH derive with infinity EC public point (invalid-curve attack): rejected with CKR_KEY_INDIGESTIBLE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', '. Direction = reject-valid → functional gap (LOW).

### `test_secret_key_value_len.py` (3 findings)

#### F061 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:41c0c144697f7ac5`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestExistingSecretKeyValueLen::test_copy_secret_key_with_oversized_value_len_does_not_crash`
- **Message:** Failed: C_CopyObject(secret key, CKA_VALUE_LEN=0xffffffffffffffff): subprocess failed with exit code 1
stdout: TARGET_RV:0x00000000
VALUE_LEN_RV:0x00000000
VALUE_LEN_VALUE:18446744073709551615
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlot
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F062 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:7035aa92bbdbd0bc`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestExistingSecretKeyValueLen::test_set_secret_key_oversized_value_len_does_not_crash`
- **Message:** Failed: C_SetAttributeValue(secret key, CKA_VALUE_LEN=0xffffffffffffffff): subprocess failed with exit code 1
stdout: TARGET_RV:0x00000000
VALUE_LEN_RV:0x00000000
VALUE_LEN_VALUE:18446744073709551615
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F063 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:e2b8c55d1c25d917`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestGenerateKeySecretKeyValueLen::test_generic_secret_generate_key_oversized_value_len_rejects_cleanly`
- **Message:** Failed: C_GenerateKey(GENERIC_SECRET, CKA_VALUE_LEN=0xffffffffffffffff): module crashed with signal 6
stdout: CONTROL_BEGIN:32
CONTROL_RV:0x00000000
CONTROL_RV_NAME:CKR_OK
CONTROL_VALUE_LEN_RV:0x00000000
CONTROL_VALUE_LEN:32
TARGET_BEGIN:18446744073709551615
stderr: thread '<unnamed>' (317) panicked
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_access_levels.py` (2 findings)

#### F064 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c406a8eaf0c54026#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_access_levels.py::TestPublicSessionRestrictions::test_public_create_private_session_object_rejected`
- **Message:** Failed: public (unauthenticated) session created a CKA_PRIVATE=True session object (PKCS#11 requires CKR_USER_NOT_LOGGED_IN): claimed the protection then violated it (self-contradiction)
- **Evidence:** kryoptic-main allows an unauthenticated (public) session to C_CreateObject a CKA_PRIVATE=True session object with CKR_OK; PKCS#11 requires CKR_USER_NOT_LOGGED_IN (test_access_levels.py:1590 test_public_create_private_session_object_rejected -> classify_policy_enforcement violated). Type-B access-control self-contradiction: private object created without login. Not in module-issues.md.

#### F065 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:da2c313206513792#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_access_levels.py::TestTrustedAttribute::test_wrap_with_trusted_rejects_untrusted`
- **Message:** _pytest.outcomes.XFailed: C_WrapKey of a CKA_WRAP_WITH_TRUSTED key with an untrusted wrapping key: rejected with CKR_WRAPPING_KEY_HANDLE_INVALID, expected ['CKR_ACTION_PROHIBITED', 'CKR_KEY_NOT_WRAPPABLE']
- **Evidence:** kryptic-main C_WrapKey of a CKA_WRAP_WITH_TRUSTED key with an untrusted wrapping key returns CKR_WRAPPING_KEY_HANDLE_INVALID; spec prefers CKR_ACTION_PROHIBITED / CKR_KEY_NOT_WRAPPABLE. Clean reject; policy is enforced (wrap refused), only the code differs.

### `test_aes_kdf.py` (1 findings)

#### F066 [CRITICAL/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:bbe36dcd8a03c859#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_aes_kdf.py::TestAESCBCEncryptData::test_derive_different_iv`
- **Message:** AssertionError: assert b'\x9aH\xa4L\x84.\x9f~\\<(\xc2\xd0\xaf\xb9G' != b'\x9aH\xa4L\x84.\x9f~\\<(\xc2\xd0\xaf\xb9G'
- **Evidence:** kryoptic-main CKM_AES_CBC_ENCRYPT_DATA derivation produces BYTE-IDENTICAL derived keys (CKA_VALUE) for two different IVs (0x00..0x0f vs 0x10..0x1f) with identical base key+data: test_aes_kdf.py:366 assert v1 != v2 fails (both 0x9a48a44c...). The IV security parameter has ZERO effect on the CBC-KDF output -> Type-A crypto-correctness break; CBC-KDF that ignores IV is broken.

### `test_aes_modes.py` (1 findings)

#### F067 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:28816822dee428b4#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_aes_modes.py::TestAESCTS::test_aes_cts_roundtrip`
- **Message:** _pytest.outcomes.XFailed: CKM_AES_CTS advertised but encrypt is not operational: CKR_DEVICE_ERROR
- **Evidence:** Capability gap: CKM_AES_CTS advertised but encrypt is not operational: CKR_DEVICE_ERROR. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_buffers.py` (1 findings)

#### F068 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0f0f879139c47fd3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_buffers.py::TestOutputBufferEdgeCases::test_sign_final_buffer_too_small_then_correct`
- **Message:** AssertionError: After CKR_BUFFER_TOO_SMALL, pulSize must be 256 (RSA-2048); got 16
assert 16 == 256
 +  where 16 = c_ulong(16).value
- **Evidence:** kryptic-main C_SignFinal with undersized buffer returns CKR_BUFFER_TOO_SMALL but reports pulSize=16 instead of 256 (RSA-2048 signature size); assert 16 == 256. Wrong required-length on the buffer-too-small retry path. test_buffers.py:TestOutputBufferEdgeCases.

### `test_dh_key_agreement.py` (1 findings)

#### F069 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4a9677e54c0ef1e4#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_dh_key_agreement.py::TestDHKeyAgreement::test_dh_derive_rejects_malformed_peer_public_value`
- **Message:** _pytest.outcomes.XFailed: CKM_DH_PKCS_DERIVE malformed peer public value: rejected with CKR_KEY_INDIGESTIBLE, expected ['CKR_ARGUMENTS_BAD', 'CKR_DOMAIN_PARAMS_INVALID', 'CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CKM_DH_PKCS_DERIVE malformed peer public value: rejected with CKR_KEY_INDIGESTIBLE, expected ['CKR_ARGUMENTS_BAD', 'CKR_DOMAIN_PARAMS_INVALID', 'CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

### `test_errors.py` (2 findings)

#### F070 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6d9fb730e7f542c6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_errors.py::TestInvalidOperations::test_invalid_mechanism_param`
- **Message:** _pytest.outcomes.XFailed: C_EncryptInit with an undersized AES-CBC-PAD IV: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

#### F071 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6a48ba1d79747bc5`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_errors.py::TestEmptyInputs::test_encrypt_empty_data`
- **Message:** _pytest.outcomes.XFailed: C_Encrypt (length query) of empty data under AES-CBC-PAD: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_DATA_LEN_RANGE']
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

### `test_hkdf_extended.py` (2 findings)

#### F072 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0822e96f357edd25#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_hkdf_extended.py::TestHKDFData::test_hkdf_data_derive`
- **Message:** _pytest.outcomes.XFailed: HKDF_DATA derive failed: CKR_TEMPLATE_INCONSISTENT
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: HKDF_DATA derive failed: CKR_TEMPLATE_INCONSISTENT. Direction = reject-valid → functional gap (LOW).

#### F073 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6dbf52a001ebb0f8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_hkdf_extended.py::TestHKDFKeyGen::test_hkdf_key_gen_basic[CKK_GENERIC_SECRET]`
- **Message:** _pytest.outcomes.XFailed: CKM_HKDF_KEY_GEN advertised but key_type=0x10 keygen rejected: CKR_TEMPLATE_INCONSISTENT
- **Evidence:** Keygen capability gap: CKM_HKDF_KEY_GEN advertised but key_type=0x10 keygen rejected: CKR_TEMPLATE_INCONSISTENT.

### `test_kem.py` (2 findings)

#### F074 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5642e82e9ed25f6d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_kem.py::TestMLKEMKeyDerivation::test_encapsulate_produces_aes128_key`
- **Message:** _pytest.outcomes.XFailed: ML-KEM AES-128 encapsulate not operational: CKR_TEMPLATE_INCONSISTENT
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ML-KEM AES-128 encapsulate not operational: CKR_TEMPLATE_INCONSISTENT. Direction = reject-valid → functional gap (LOW).

#### F075 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4defc75cf7d1ac46#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_kem.py::TestMLKEMKeyDerivation::test_encapsulate_produces_aes256_key`
- **Message:** _pytest.outcomes.XFailed: ML-KEM AES-256 encapsulate not operational: CKR_TEMPLATE_INCONSISTENT
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ML-KEM AES-256 encapsulate not operational: CKR_TEMPLATE_INCONSISTENT. Direction = reject-valid → functional gap (LOW).

### `test_mech_attribute.py` (1 findings)

#### F076 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4cff87dd14fb6d23#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_attribute.py::TestKeyAttributes::test_key_type_matches_template[PKCS5_PBKD2]`
- **Message:** _pytest.outcomes.XFailed: PKCS5_PBKD2 keygen rejected at runtime: CKR_TEMPLATE_INCONSISTENT
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: PKCS5_PBKD2 keygen rejected at runtime: CKR_TEMPLATE_INCONSISTENT. Direction = reject-valid → functional gap (LOW).

### `test_mech_encrypt.py` (2 findings)

#### F077 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9b1df1fb277178cd`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[AES_CCM]`
- **Message:** _pytest.outcomes.XFailed: AES_CCM:encrypt: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F078 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f0487c1b18ffd25b`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[RSA_X_509]`
- **Message:** _pytest.outcomes.XFailed: RSA_X_509:encrypt: advertised but not operational (CKR_GENERAL_ERROR)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_keygen.py` (1 findings)

#### F079 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b5ec158f0ed0ae1a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_keygen.py::TestMechKeygen::test_generate_key[PKCS5_PBKD2]`
- **Message:** _pytest.outcomes.XFailed: PKCS5_PBKD2 keygen rejected at runtime: CKR_TEMPLATE_INCONSISTENT
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: PKCS5_PBKD2 keygen rejected at runtime: CKR_TEMPLATE_INCONSISTENT. Direction = reject-valid → functional gap (LOW).

### `test_mech_message.py` (3 findings)

#### F080 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7bed6bf851c2019f#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_message.py::TestMessageEncrypt::test_message_encrypt_aes_gcm_generated_iv_writeback`
- **Message:** AssertionError: C_EncryptMessage did not write generated IV to pIv
assert False
 +  where False = any(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
- **Evidence:** kryoptic-main C_EncryptMessage (AES-GCM, message API v3.0) returns CKR_OK but leaves the generated-IV pIv buffer all-zero (test_mech_message.py test_message_encrypt_aes_gcm_generated_iv_writeback: assert any(non-zero) is False). The generated IV is never written back -> ciphertext is unusable (decryptor cannot recover IV). Wrong/incomplete output on an advertised operational message mechanism.

#### F081 [LOW/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:37c9050cb8917587#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_message.py::TestRegistryMessagePermission::test_registry_message_encrypt_without_flag[AES_CCM]`
- **Message:** _pytest.outcomes.XFailed: AES_CCM keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** kryptic-main AES-CCM message-operation keygen/setup rejected at runtime with CKR_MECHANISM_INVALID (2 cases). CCM operability gap; per task context CCM operability probes were recently fixed, so this may be stale. Advertised-but-not-operational soft-token caveat, no security impact.

#### F082 [LOW/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:1895ade7977655d6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_message.py::TestRegistryMessagePermission::test_registry_message_encrypt_without_flag[AES_GCM]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** kryptic-main AES-GCM message-operation keygen/setup rejected at runtime with CKR_MECHANISM_INVALID (2 cases). Same message-API operability caveat shape as the CCM case; clean reject, no security impact.

### `test_mech_multipart.py` (6 findings)

#### F083 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b3133cf4abb509e3`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD:multipart-decrypt: advertised but not operational (CKR_ENCRYPTED_DATA_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F084 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8285760c9518b8d6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[AES_CTS]`
- **Message:** _pytest.outcomes.XFailed: AES_CTS:multipart-decrypt: advertised but not operational (CKR_OPERATION_NOT_INITIALIZED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F085 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ee33fe931857f04d`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[EDDSA]`
- **Message:** _pytest.outcomes.XFailed: EDDSA:multipart-sign: advertised but not operational (CKR_DEVICE_ERROR)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F086 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4870df335f806e72`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[HASH_ML_DSA]`
- **Message:** _pytest.outcomes.XFailed: HASH_ML_DSA:multipart-sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F087 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:154b78ec0661f7ef`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[TLS12_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS12_MAC:multipart-sign: advertised but not operational (CKR_ARGUMENTS_BAD)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F088 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2124e13ea83bfac4`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[TLS_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS_MAC:multipart-sign: advertised but not operational (CKR_ARGUMENTS_BAD)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_negative.py` (94 findings)

#### F089 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:14d160852925cedc#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F090 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cf325ba2227d87a4#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F091 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fc70744408b0b2af#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_CCM]`
- **Message:** _pytest.outcomes.XFailed: AES_CCM keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CCM keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F092 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:87c06c87989a07cc#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F093 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7e753677c034b228#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_CTS]`
- **Message:** _pytest.outcomes.XFailed: AES_CTS keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTS keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F094 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:21b4db72feccfc50#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_GCM]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_GCM keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F095 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e1bf498e43a63335#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F096 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7ee30eda5e29aa4f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA512_224_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA512_224_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_224_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F097 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5b19c980cfeb9aa7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA512_256_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA512_256_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_256_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F098 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:62392f753159d8ec#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 7
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_derive_wrong_key_type[CONCATENATE_BASE_AND_KEY]`
- **Message:** _pytest.outcomes.XFailed: CONCATENATE_BASE_AND_DATA keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CONCATENATE_BASE_AND_DATA keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F099 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c6475405b03099b0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_KEY_WRAP]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_WRAP keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_WRAP keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F100 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4f197c777d32c660#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_KEY_WRAP_KWP]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_WRAP_KWP keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_WRAP_KWP keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F101 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b1a8ef0b4b2f6897#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[AES_CMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: AES_CMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F102 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c76792b925ef9c89#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[AES_MAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: AES_MAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_MAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F103 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:129ccf349b4d6a7f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA224_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA224_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA224_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F104 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:587ffbe066efb319#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA256_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA256_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F105 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:46c9eeaced369087#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA384_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA384_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA384_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F106 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:abd54cab31ff0d2f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_224_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_224_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_224_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F107 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:bd11c624c4629b70#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_256_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_256_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_256_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F108 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8265447e90957dda#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_384_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_384_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_384_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F109 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:36a557a8f9b01170#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_512_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_512_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_512_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F110 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:14b4ed2794f9d2f2#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA512_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA512_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F111 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d05fbbd48db99ecc#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA_1_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA_1_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA_1_HMAC_GENERAL C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F112 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6675e3c3b3fa7752#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[HASH_ML_DSA]`
- **Message:** _pytest.outcomes.XFailed: HASH_ML_DSA C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: HASH_ML_DSA C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F113 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:92d9f2d6c703bd89#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F114 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:42c5c27f621c8705#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA1_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA1_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA1_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F115 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b400969c84247384#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA224_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA224_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA224_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F116 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:56103615a36808d7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA256_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA256_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA256_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F117 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5bb50cf8346238a9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA384_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA384_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA384_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F118 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8155d36a144cca92#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_224_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA3_224_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_224_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F119 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:90a449046b041c1d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_256_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA3_256_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_256_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F120 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:be4f1dedbe7b96e9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_384_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA3_384_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_384_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F121 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3a0eb54f0823d918#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA3_512_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA3_512_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_512_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F122 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:910db0c8259d0534#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA512_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA512_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_RSA_PKCS_PSS C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F123 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0b8c1f45d3377e8e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_derive_missing_required_param[CONCATENATE_DATA_AND_BASE]`
- **Message:** _pytest.outcomes.XFailed: CONCATENATE_DATA_AND_BASE keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CONCATENATE_DATA_AND_BASE keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F124 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e6a99732019a4e46#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_derive_missing_required_param[EXTRACT_KEY_FROM_KEY]`
- **Message:** _pytest.outcomes.XFailed: EXTRACT_KEY_FROM_KEY keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: EXTRACT_KEY_FROM_KEY keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F125 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b9110d7188b29a3a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_derive_missing_required_param[SHA3_224_KEY_DERIVE]`
- **Message:** _pytest.outcomes.XFailed: SHA3_224_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_224_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F126 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fc0775eafd26e269#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_derive_missing_required_param[SHA3_256_KEY_DERIVE]`
- **Message:** _pytest.outcomes.XFailed: SHA3_256_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_256_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F127 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b4bd56695c2b0d3e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_derive_missing_required_param[SHA3_384_KEY_DERIVE]`
- **Message:** _pytest.outcomes.XFailed: SHA3_384_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_384_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F128 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:debdd26c825f7b73#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_derive_missing_required_param[SHA3_512_KEY_DERIVE]`
- **Message:** _pytest.outcomes.XFailed: SHA3_512_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_512_KEY_DERIVE keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F129 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cad502aa93597637#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_derive_missing_required_param[XOR_BASE_AND_DATA]`
- **Message:** _pytest.outcomes.XFailed: XOR_BASE_AND_DATA keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: XOR_BASE_AND_DATA keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F130 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:00dd819ac803fbac#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC_PAD C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F131 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9b9d2fd98778d08b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[RSA_PKCS_OAEP]`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_OAEP C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RSA_PKCS_OAEP C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F132 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:730aa649bab1a873#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[TLS12_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS12_MAC C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: TLS12_MAC C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F133 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:08fd0b6b138ef16c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[TLS_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS_MAC C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: TLS_MAC C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F134 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e9f1fb6740907c07#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[AES_CFB1]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB1 keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB1 keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F135 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6b935a3fc21a416c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[AES_CFB128]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB128 keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB128 keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F136 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f53a3382bc22faaf#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[AES_CFB8]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB8 keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB8 keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F137 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5bb440afe96fc459#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[AES_OFB]`
- **Message:** _pytest.outcomes.XFailed: AES_OFB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_OFB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F138 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a5de13d3e1836f0a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[AES_CMAC]`
- **Message:** _pytest.outcomes.XFailed: AES_CMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F139 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cacf7fbed64d9579#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[AES_MAC]`
- **Message:** _pytest.outcomes.XFailed: AES_MAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_MAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F140 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2ebc95a0872628bc#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA224_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA224_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA224_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F141 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:aee2a1f3709129eb#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA256_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA256_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F142 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:68e44f4be1b307bb#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA384_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA384_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA384_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F143 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d06df16621132de2#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA3_224_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA3_224_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_224_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F144 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c1a3bb632cf78e23#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA3_256_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA3_256_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_256_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F145 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:583d8d6a9b5ab18c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA3_384_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA3_384_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_384_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F146 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a2f094ba5d9b7f8d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA3_512_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA3_512_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA3_512_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F147 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b5564f08eb7601c3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA512_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA512_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F148 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:04aa2824dc4795a6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA_1_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA_1_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA_1_HMAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F149 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:099b378aa814bf69#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[TLS12_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS12_MAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: TLS12_MAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F150 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b3d4c08fccc0782e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[TLS_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS_MAC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: TLS_MAC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F151 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:eb73e0f7a7fac184#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[TLS12_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS12_MAC sign with wrong key type: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: TLS12_MAC sign with wrong key type: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F152 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0eafce434dc70c50#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[TLS_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS_MAC sign with wrong key type: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: TLS_MAC sign with wrong key type: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F153 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9008ea178f027749#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[TLS12_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS12_MAC verify with wrong key type: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: TLS12_MAC verify with wrong key type: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F154 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fec84ae5eab71dea#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[TLS_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS_MAC verify with wrong key type: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: TLS_MAC verify with wrong key type: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F155 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e184ea858ced48b7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_CCM]`
- **Message:** _pytest.outcomes.XFailed: AES_CCM wrap with wrong key type: rejected with CKR_MECHANISM_PARAM_INVALID, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CCM wrap with wrong key type: rejected with CKR_MECHANISM_PARAM_INVALID, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F156 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:bfc4e726d5ea8165#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F157 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c99d4829b4510f26#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CCM]`
- **Message:** _pytest.outcomes.XFailed: AES_CCM C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CCM C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F158 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8e9bb52c20755e42#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CFB1]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB1 C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB1 C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F159 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b801bb4d8780849f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CFB128]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB128 C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB128 C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F160 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:42236c70a6f40a74#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CFB8]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB8 C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB8 C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F161 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:aec5366bf9300766#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F162 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1cee944c3dbe3f40#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CTS]`
- **Message:** _pytest.outcomes.XFailed: AES_CTS C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTS C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F163 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:13ee6165fa72a704#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_GCM]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_GCM C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F164 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c2ae389bcaa32502#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_OFB]`
- **Message:** _pytest.outcomes.XFailed: AES_OFB C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_OFB C_EncryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F165 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:78a16475d6388139#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F166 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fcb6f010ba146ce9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_CCM]`
- **Message:** _pytest.outcomes.XFailed: AES_CCM C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CCM C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F167 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ae78a0298844b77e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_CFB1]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB1 C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB1 C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F168 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0aae812ea3979a7c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_CFB128]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB128 C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB128 C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F169 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0bcdcc9a19e5560a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_CFB8]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB8 C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB8 C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F170 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9390991ce9d28e5a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F171 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:12b6942fbf00b631#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_CTS]`
- **Message:** _pytest.outcomes.XFailed: AES_CTS C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTS C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F172 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:74d2d863f5d03b73#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_GCM]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_GCM C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F173 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0a7e2075531b87e3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_OFB]`
- **Message:** _pytest.outcomes.XFailed: AES_OFB C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_OFB C_DecryptInit with missing required params: rejected with CKR_ARGUMENTS_BAD, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F174 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:982d5b62ed0bd53f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_malformed_required_param[EDDSA]`
- **Message:** _pytest.outcomes.XFailed: EDDSA C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: EDDSA C_SignInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F175 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:55bae0ca953e4dc1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[AES_ECB_ENCRYPT_DATA]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB_ENCRYPT_DATA keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_ECB_ENCRYPT_DATA keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F176 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0d433efc23bfc222#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[SHA1_KEY_DERIVATION]`
- **Message:** _pytest.outcomes.XFailed: SHA1_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA1_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F177 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7ebe4effd4729b79#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[SHA224_KEY_DERIVATION]`
- **Message:** _pytest.outcomes.XFailed: SHA224_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA224_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F178 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:82123faa342281a8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[SHA256_KEY_DERIVATION]`
- **Message:** _pytest.outcomes.XFailed: SHA256_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA256_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F179 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9905bace16373d7c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[SHA384_KEY_DERIVATION]`
- **Message:** _pytest.outcomes.XFailed: SHA384_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA384_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F180 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e577f0cd34953551#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[SHA512_224_KEY_DERIVATION]`
- **Message:** _pytest.outcomes.XFailed: SHA512_224_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_224_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F181 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ed5d4d43a50ef56c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[SHA512_256_KEY_DERIVATION]`
- **Message:** _pytest.outcomes.XFailed: SHA512_256_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_256_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F182 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:dbeeb247bef8400f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_derive_without_flag[SHA512_KEY_DERIVATION]`
- **Message:** _pytest.outcomes.XFailed: SHA512_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_KEY_DERIVATION keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_mech_sign.py` (10 findings)

#### F183 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:dfb4cba2181a9d8d`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[EDDSA]`
- **Message:** _pytest.outcomes.XFailed: EDDSA:sign: advertised but not operational (CKR_DEVICE_ERROR)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F184 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0fa26083f7c5e3c5`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[HASH_ML_DSA]`
- **Message:** _pytest.outcomes.XFailed: HASH_ML_DSA:sign: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F185 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0f4e91a70e160289`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[RSA_X_509]`
- **Message:** _pytest.outcomes.XFailed: RSA_X_509:sign: advertised but not operational (CKR_DEVICE_ERROR)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F186 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2bbc781ff7236193`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[TLS12_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS12_MAC:sign: advertised but not operational (CKR_ARGUMENTS_BAD)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F187 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:870b0a2776ba1a37`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[TLS_MAC]`
- **Message:** _pytest.outcomes.XFailed: TLS_MAC:sign: advertised but not operational (CKR_ARGUMENTS_BAD)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F188 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:76477581739d7529`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[ECDSA_SHA224]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA224:key-import: advertised but not operational (EC private key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F189 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ba3de2adc638fc1c`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[ECDSA_SHA256]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA256:key-import: advertised but not operational (EC private key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F190 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0ad85cb49639ae25`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[ECDSA_SHA384]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA384:key-import: advertised but not operational (EC private key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F191 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:09b6c20e81dcc754`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[ECDSA_SHA512]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA512:key-import: advertised but not operational (EC private key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F192 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d7a7599b683c294b`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[EDDSA]`
- **Message:** _pytest.outcomes.XFailed: EDDSA:kat-sign: advertised but not operational (CKR_DEVICE_ERROR)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_wrap.py` (3 findings)

#### F193 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:61b377d566ddfc55`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_wrap.py::TestMechWrapRoundtrip::test_wrap_unwrap_aes_key[AES_CCM]`
- **Message:** _pytest.outcomes.XFailed: AES_CCM:wrap: advertised but not operational (CKR_ARGUMENTS_BAD)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F194 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9c1ceb5230c8981c`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_wrap.py::TestMechWrapRoundtrip::test_wrap_unwrap_aes_key[AES_GCM]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM:wrap: advertised but not operational (CKR_ARGUMENTS_BAD)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F195 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:371f885fb9d19f20`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_wrap.py::TestMechWrapRoundtrip::test_wrap_unwrap_aes_key[RSA_X_509]`
- **Message:** _pytest.outcomes.XFailed: RSA_X_509:wrap: advertised but not operational (CKR_GENERAL_ERROR)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_message_crypto.py` (2 findings)

#### F196 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:63e7b84ba154b194#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_single`
- **Message:** _pytest.outcomes.XFailed: advertised message encrypt rejected (CKM_AES_CBC): CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: advertised message encrypt rejected (CKM_AES_CBC): CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F197 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:10998222881136b2#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_multipart`
- **Message:** _pytest.outcomes.XFailed: C_MessageEncryptInit rejected advertised message operation: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_MessageEncryptInit rejected advertised message operation: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_misc_kdf.py` (2 findings)

#### F198 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1ffad442544cdfd3#phase6`
- **Direction:** `WRONG_OUTPUT` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_misc_kdf.py::TestExtractKeyFromKey::test_extract_from_offset_zero`
- **Message:** AssertionError: Expected 000102030405060708090a0b0c0d0e0f, got 010303070507070f090b0b0f0d0f0f1f111313171517171f191b1b1f1d1f1f1f
assert b'\x01\x03\x0...d\x1f\x1f\x1f' == b'\x00\x01\x0...x0c\r\x0e\x0f'
  
  At index 0 diff: b'\x01' != b'\x00'
  Use -v to get more diff
- **Evidence:** kryptic returns CKR_OK for CKM_EXTRACT_KEY_FROM_KEY at bit offset 0 but produces 32 bytes of bit-transformed output (010303070507070f...) instead of the first 16 bytes of the base key (000102...0f) (test_misc_kdf.py:159). EXTRACT_KEY_FROM_KEY is a simple sub-key byte slice (PKCS#11 Sec.6.18.5); there is no parameter-encoding ambiguity for this mechanism, so returning a different-length transformed value is an unambiguous kryptic derive bug. Type A wrong-output.

#### F199 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7615c2e7aa87d32e#phase6`
- **Direction:** `WRONG_OUTPUT` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_misc_kdf.py::TestExtractKeyFromKey::test_extract_at_byte_boundary_offset`
- **Message:** AssertionError: Expected 101112131415161718191a1b1c1d1e1f, got 111313171517171f191b1b1f1d1f1f1f010303070507070f090b0b0f0d0f0f1f
assert b'\x11\x13\x1...r\x0f\x0f\x1f' == b'\x10\x11\x1...c\x1d\x1e\x1f'
  
  At index 0 diff: b'\x11' != b'\x10'
  Use -v to get more diff
- **Evidence:** kryptic returns CKR_OK for CKM_EXTRACT_KEY_FROM_KEY at a byte-boundary offset but produces a 32-byte bit-transformed value (11131317...) instead of the expected 16-byte slice (101112...1f) of the base key (test_misc_kdf.py:231). Same unambiguous derive bug as the offset-zero sibling: EXTRACT_KEY_FROM_KEY must return the requested byte slice, not a transformed over-length value. Type A wrong-output.

### `test_operation_termination.py` (8 findings)

#### F200 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0694006e303c2696#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-input]`
- **Message:** Failed: C_Encrypt with NULL input pointer returned CKR_ARGUMENTS_BAD but left the encrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** kryptic-main null-arg lifecycle: C_Encrypt(single) with NULL input pointer returns CKR_ARGUMENTS_BAD but leaves the encrypt op ACTIVE (next C_EncryptInit -> CKR_OPERATION_ACTIVE). Spec requires C_Encrypt to ALWAYS terminate the operation. Type-C self-contradiction; cascades CKR_OPERATION_ACTIVE onto later tests.

#### F201 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c8b3a59e5156f0b0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-length]`
- **Message:** Failed: C_Encrypt with NULL length pointer returned CKR_ARGUMENTS_BAD but left the encrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** kryptic-main: C_Encrypt(single) NULL length pointer -> CKR_ARGUMENTS_BAD but encrypt op left ACTIVE. Same Type-C lifecycle root as the null-arg cohort (test_operation_termination.py:489).

#### F202 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d1d7a1ce3771bd1a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-update-input]`
- **Message:** Failed: C_EncryptUpdate with NULL input pointer returned CKR_ARGUMENTS_BAD but left the encrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** kryptic-main: C_EncryptUpdate NULL input pointer -> CKR_ARGUMENTS_BAD but encrypt op left ACTIVE. Same Type-C lifecycle root as the null-arg cohort (test_operation_termination.py:489).

#### F203 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2b8fd0ae8d585cfd#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-update-length]`
- **Message:** Failed: C_EncryptUpdate with NULL length pointer returned CKR_ARGUMENTS_BAD but left the encrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** kryptic-main: C_EncryptUpdate NULL length pointer -> CKR_ARGUMENTS_BAD but encrypt op left ACTIVE. Same Type-C lifecycle root as the null-arg cohort (test_operation_termination.py:489).

#### F204 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7f83ae8d23f73e01#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-input]`
- **Message:** Failed: C_Decrypt with NULL input pointer returned CKR_ARGUMENTS_BAD but left the decrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** kryptic-main: C_Decrypt(single) NULL input pointer -> CKR_ARGUMENTS_BAD but decrypt op left ACTIVE. Same Type-C lifecycle root as the null-arg cohort (test_operation_termination.py:489).

#### F205 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:dedf25e2a49baf74#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-length]`
- **Message:** Failed: C_Decrypt with NULL length pointer returned CKR_ARGUMENTS_BAD but left the decrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** kryptic-main: C_Decrypt(single) NULL length pointer -> CKR_ARGUMENTS_BAD but decrypt op left ACTIVE. Same Type-C lifecycle root as the null-arg cohort (test_operation_termination.py:489).

#### F206 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7bcb31816002f619#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-update-input]`
- **Message:** Failed: C_DecryptUpdate with NULL input pointer returned CKR_ARGUMENTS_BAD but left the decrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** kryptic-main: C_DecryptUpdate NULL input pointer -> CKR_ARGUMENTS_BAD but decrypt op left ACTIVE. Same Type-C lifecycle root as the null-arg cohort (test_operation_termination.py:489).

#### F207 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f56d2a08ace19b07#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[decrypt-update-length]`
- **Message:** Failed: C_DecryptUpdate with NULL length pointer returned CKR_ARGUMENTS_BAD but left the decrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** kryptic-main: C_DecryptUpdate NULL length pointer -> CKR_ARGUMENTS_BAD but decrypt op left ACTIVE. Same Type-C lifecycle root as the null-arg cohort (test_operation_termination.py:489).

### `test_ro_session_restrictions.py` (1 findings)

#### F208 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3c162c8f7bc863a8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_ro_session_restrictions.py::TestROWrapUnwrapRestrictions::test_unwrap_to_session_object_in_ro_succeeds`
- **Message:** _pytest.outcomes.XFailed: Module overly restricts RO session unwrap (Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT; expected one of: CKR_OK)
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: Module overly restricts RO session unwrap (Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT; expected one of: CKR_OK). Direction = reject-valid → functional gap (LOW).

### `test_set_attribute.py` (3 findings)

#### F209 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7de735f304368f99#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_set_attribute.py::TestSetAttributeAtomicity::test_set_attribute_mixed_template_is_atomic`
- **Message:** Failed: C_SetAttributeValue mixed mutable/read-only template: attribute(s) could not be read back after the write (Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID) -- the object was left in an inconsistent state
- **Evidence:** kryptic's C_SetAttributeValue on an AES key with a mixed mutable+read-only template returns without rejecting, then C_GetAttributeValue on the object returns CKR_ATTRIBUTE_VALUE_INVALID (test_set_attribute.py:193-199 read-back via _read_back_or_fail). The object is left unreadable after an accepted write: claimed success then broken state -> Type C self-contradiction, fail per the classification model.

#### F210 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:33f58e21cebe13cf#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_set_attribute.py::TestSetAttributeNegative::test_cannot_change_class`
- **Message:** Failed: write read-only CKA_CLASS (PKCS#11 Base v3.0 Table 15): attribute(s) could not be read back after the write (Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID) -- the object was left in an inconsistent state
- **Evidence:** kryptic accepts a C_SetAttributeValue writing read-only CKA_CLASS (PKCS#11 Base v3.0 Table 15) on an AES key, then C_GetAttributeValue returns CKR_ATTRIBUTE_VALUE_INVALID (test_set_attribute.py:232 via _classify_readonly_write/_read_back_or_fail). Read-only write accepted and the object is left in a broken readback state -> Type C self-contradiction.

#### F211 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3084d1d72871f1c4#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_set_attribute.py::TestSetAttributeNegative::test_cannot_change_key_type`
- **Message:** Failed: write read-only CKA_KEY_TYPE (PKCS#11 Base v3.0 Table 15): attribute(s) could not be read back after the write (Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID) -- the object was left in an inconsistent state
- **Evidence:** kryptic accepts a C_SetAttributeValue writing read-only CKA_KEY_TYPE (Table 15) to CKK_RSA on an AES key, then C_GetAttributeValue returns CKR_ATTRIBUTE_VALUE_INVALID (test_set_attribute.py:247 via _classify_readonly_write). Same Type C self-contradiction as the CKA_CLASS sibling: read-only write accepted then object unreadable.

### `test_sp800_108_kdf.py` (2 findings)

#### F212 [HIGH/PROVIDER_BUG] — 🔍 MANUAL_REVIEW
- **Signature:** `sha1:425ead980697b227#phase6`
- **Direction:** `WRONG_OUTPUT` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_sp800_108_kdf.py::TestSP800108CounterKDF::test_derive_aes128`
- **Message:** AssertionError: CKM_SP800_108_COUNTER_KDF AES-128 output mismatch: got 4466e5d45b01b34f06293859334f97a8, expected caff7a6a35ca9b35afcc64fa658d8bc2
assert b'Df\xe5\xd4[...)8Y3O\x97\xa8' == b'\xca\xffzj5...e\x8d\x8b\xc2'
  
  At index 0 diff: b'D' != b'\xca'
  Use -v to get more diff
- **Evidence:** kryptic returns CKR_OK for CKM_SP800_108_COUNTER_KDF derive but the 16-byte output (4466e5d4...) does not match the textbook NIST SP 800-108 counter construction (counter||label||0x00||context||L, HMAC-SHA256) computed from the same base key/label/context (test_sp800_108_kdf.py:431-455, reference at :91-108). Type A wrong-output on a successful derive. Manual review needed to confirm whether kryptic serializes CK_SP800_108_KDF_PARAMS data array differently from the harness reference (a known PKC

#### F213 [HIGH/PROVIDER_BUG] — 🔍 MANUAL_REVIEW
- **Signature:** `sha1:a2194647ac713ec4#phase6`
- **Direction:** `WRONG_OUTPUT` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_sp800_108_kdf.py::TestSP800108FeedbackKDF::test_derive_aes128`
- **Message:** AssertionError: CKM_SP800_108_FEEDBACK_KDF AES-128 output mismatch: got c001b502468dcb6f86f05c869ab5986d, expected 0eb73e600b11c4474e6fb84c226c8b1a
assert b'\xc0\x01\xb...\x9a\xb5\x98m' == b'\x0e\xb7>`\...b8L"l\x8b\x1a'
  
  At index 0 diff: b'\xc0' != b'\x0e'
  Use -v to get more diff
- **Evidence:** kryptic returns CKR_OK for CKM_SP800_108_FEEDBACK_KDF derive but the output (c001b502...) does not match the NIST SP 800-108 feedback construction (IV||fixed_input_suffix, HMAC-SHA256) computed from the same inputs (test_sp800_108_kdf.py:614-640, reference at :111-129). Type A wrong-output on a successful derive. Same parameter-serialization caveat as the counter-KDF sibling; confirm CK_SP800_108_FEEDBACK_KDF_PARAMS encoding before reporting.

### `test_tls12.py` (1 findings)

#### F214 [HIGH/PROVIDER_BUG] — 🔍 MANUAL_REVIEW
- **Signature:** `sha1:f98e714feabb1580#phase6`
- **Direction:** `WRONG_OUTPUT` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_tls12.py::TestTLS12KDF::test_tls12_kdf_context_data_exact_vector`
- **Message:** AssertionError: CKM_TLS12_KDF context-data output mismatch: got 41518e9244518c692fc807176be3de3b18a61781f49babe5dcea19dbfa71fc54, expected 5c0125c5f281488f681349499f252df0d29934469aabc15136b0a6a78a4b39d7
assert b'AQ\x8e\x92D...xdb\xfaq\xfcT' == b'\\\x01%\xc5...xa7\x8aK9\xd7'
  
  At index 0 diff: b'
- **Evidence:** kryptic returns CKR_OK for CKM_TLS12_KDF derive (context-data exact vector) but the output (41518e92...) does not match the TLS 1.2 PRF (HMAC-SHA256) reference (5c0125c5...) computed from the same inputs (test_tls12.py:1045-1090). Type A wrong-output on a successful derive. Manual review to confirm the CKM_TLS12_KDF / TLS12_PARAMS field encoding matches the harness reference before reporting.

### `test_wycheproof_aes.py` (27 findings)

#### F215 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:062ada4a42d7a109`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc14-invalid]`
- **Message:** Failed: AES-KW unwrap tc14-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F216 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:5d509a10c36f9735`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc15-invalid]`
- **Message:** Failed: AES-KW unwrap tc15-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F217 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:5f758fbb82ac7bf9`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc16-invalid]`
- **Message:** Failed: AES-KW unwrap tc16-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F218 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:1bf49cb6e7185396`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc17-invalid]`
- **Message:** Failed: AES-KW unwrap tc17-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F219 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:613f8f90e11b0613`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc18-invalid]`
- **Message:** Failed: AES-KW unwrap tc18-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F220 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:acfff51b3a8a0f34`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc19-invalid]`
- **Message:** Failed: AES-KW unwrap tc19-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F221 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:b32a8bebee9d9f5f`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc20-invalid]`
- **Message:** Failed: AES-KW unwrap tc20-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F222 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:edd1bc844ffedd4b`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc21-invalid]`
- **Message:** Failed: AES-KW unwrap tc21-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F223 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:fe35f2c4ce2eebd3`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc22-invalid]`
- **Message:** Failed: AES-KW unwrap tc22-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F224 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:afaa2f6c6dcaadcb`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc56-invalid]`
- **Message:** Failed: AES-KW unwrap tc56-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F225 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:f94d3a806c9722e3`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc57-invalid]`
- **Message:** Failed: AES-KW unwrap tc57-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F226 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:a8e13618666db1bd`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc58-invalid]`
- **Message:** Failed: AES-KW unwrap tc58-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F227 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:7225ead2c99247be`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc59-invalid]`
- **Message:** Failed: AES-KW unwrap tc59-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F228 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:69d0220909ff0471`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc60-invalid]`
- **Message:** Failed: AES-KW unwrap tc60-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F229 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:2c9c7cf250e087ab`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc61-invalid]`
- **Message:** Failed: AES-KW unwrap tc61-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F230 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:21180d6ef5dd1c33`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc62-invalid]`
- **Message:** Failed: AES-KW unwrap tc62-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F231 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:e9c4dee10a5db568`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc63-invalid]`
- **Message:** Failed: AES-KW unwrap tc63-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F232 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:863e0de780120b63`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc64-invalid]`
- **Message:** Failed: AES-KW unwrap tc64-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F233 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:05438c0871e57e5b`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc111-invalid]`
- **Message:** Failed: AES-KW unwrap tc111-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F234 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:a94e89fe074bb070`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc112-invalid]`
- **Message:** Failed: AES-KW unwrap tc112-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F235 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:bb705b19499e6da5`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc113-invalid]`
- **Message:** Failed: AES-KW unwrap tc113-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F236 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:b9c74059b43b370b`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc114-invalid]`
- **Message:** Failed: AES-KW unwrap tc114-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F237 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:1e1bb5113864a9b6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc115-invalid]`
- **Message:** Failed: AES-KW unwrap tc115-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F238 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:edf40035d7d5f08a`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc116-invalid]`
- **Message:** Failed: AES-KW unwrap tc116-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F239 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:65e86593df4ea5c4`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc117-invalid]`
- **Message:** Failed: AES-KW unwrap tc117-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F240 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:b82e47ecb4ff0369`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc118-invalid]`
- **Message:** Failed: AES-KW unwrap tc118-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F241 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:cd0af8f1128043ca`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_key_wrap[tc119-invalid]`
- **Message:** Failed: AES-KW unwrap tc119-invalid: accepted invalid wrapped key (forged blob unwrapped)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

### `test_wycheproof_ecdh.py` (1 findings)

#### F242 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3e666ce477c47958`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3750
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py::test_ecdh[ecdh_brainpoolP224r1_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: ECDH:EC-private-import: advertised but not operational (CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_wycheproof_ecdsa.py` (1 findings)

#### F243 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a342cec35907c088`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 7872
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py::test_ecdsa_wycheproof[ecdsa_brainpoolP224r1_sha224_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: ECDSA:key-import: advertised but not operational (brainpoolp224r1: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_wycheproof_mldsa.py` (3 findings)

#### F244 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:54849be8766fe47a#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 162
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py::test_mldsa_verify[mldsa_87_verify_test.json:tc5-invalid]`
- **Message:** _pytest.outcomes.XFailed: mldsa_87_verify_test.json:tc5-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: mldsa_87_verify_test.json:tc5-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F245 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7d84627d03fa6a4e#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 124
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py::test_mldsa_verify[mldsa_65_verify_test.json:tc5-invalid]`
- **Message:** _pytest.outcomes.XFailed: mldsa_65_verify_test.json:tc5-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: mldsa_65_verify_test.json:tc5-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F246 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fb7362675469cb62#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 96
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py::test_mldsa_verify[mldsa_44_verify_test.json:tc5-invalid]`
- **Message:** _pytest.outcomes.XFailed: mldsa_44_verify_test.json:tc5-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: mldsa_44_verify_test.json:tc5-invalid: signature verification rejected with non-clean CKR: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).


## Already documented in `docs/module-issues.md` (526 findings)

These records match an existing module-issues.md entry. Not re-listed here to avoid duplication; see `verdicts.jsonl` for individual pointers.

## Not yet classified (35 groups, DEFERRED)

Per user directive m0213-m0214, classification extension stopped. These will be classified by an in-tool workflow.

Top by size:
| Group size | Direction | Test file | Signature |
|---:|---|---|---|
| 405 | CLEAN_ERROR | `test_cts.py` | `sha1:b2de5a82e3d8c7bb` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:32ffcf661afa7fa6` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:efa37755e7f28a58` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:d04910508a713209` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:bdc2e4e6fa2740a8` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:324b3e81363800f0` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:cf3cae676687778f` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:228b8b8af74f3514` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:a5d71fa1119904fd` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:b796dbd479d93391` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:53d67b9461fb7bda` |
| 16 | CLEAN_ERROR | `test_wycheproof_mlkem_encaps_modulus.py` | `sha1:e044be8483151959` |
| 12 | CLEAN_ERROR | `test_wycheproof_mlkem_encaps_modulus.py` | `sha1:db10f231f5af770a` |
| 8 | CLEAN_ERROR | `test_hash_slh_dsa.py` | `sha1:655d5cfc391c5bd6` |
| 8 | CLEAN_ERROR | `test_wycheproof_mlkem_encaps_modulus.py` | `sha1:dc5039cc84c7826d` |
