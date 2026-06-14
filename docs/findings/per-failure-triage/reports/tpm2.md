# tpm2 — Per-Failure Triage

**Effective records:** 331
**Categories:** {'PROVIDER_BUG': 194, 'UNKNOWN': 72, 'KNOWN_ISSUE': 45, 'SOFT_TOKEN_CAVEAT': 18, 'HARNESS_BUG': 2}
**Severities:** {'LOW': 204, 'MEDIUM': 94, 'INFO': 18, 'HIGH': 14, 'CRITICAL': 1}

## Findings (214)

Ordered by severity then category.

### `test_cfb128.py` (1 findings)

#### F001 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:971315973e42ca76#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2144
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/aes/test_cfb128.py::test_acvp_aes_cfb128_encrypt[AES-enc-tc1]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB128 advertised but MCT encrypt is not operational: Unexpected CK_RV CKR_GENERAL_ERROR; expected one of: CKR_OK
- **Evidence:** Capability gap: AES_CFB128 advertised but MCT encrypt is not operational: Unexpected CK_RV CKR_GENERAL_ERROR; expected one of: CKR_OK. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_acvp_ecdsa.py` (2 findings)

#### F002 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5cfbdef6ab1369f2`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 13
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py::test_acvp_ecdsa_sigver[ECDSA-SigVer-P-256-SHA2-256-tc50]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA256:key-import: advertised but not operational (P-256: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F003 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ce85992f2d4a2712`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 7
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_ecdsa.py::test_acvp_ecdsa_sigver[ECDSA-SigVer-P-256-SHA2-512-tc57]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA512:key-import: advertised but not operational (P-256: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_acvp_rsa.py` (4 findings)

#### F004 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:182d64b1d08ac4b7`
- **Direction:** `CAPABILITY_GAP` · **Outcome:** `xfail` · **Tests covered:** 162
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_rsa.py::TestRsaSigVer::test_rsa_pkcs15_verify[SigVer-pkcs15-ver-SHA-1-tc181_0]`
- **Message:** _pytest.outcomes.XFailed: SigVer-pkcs15-ver-SHA-1-tc181: SHA1_RSA_PKCS invalid-signature reject: vacuous reject -- mechanism not operational (canonical known-valid vector verifies False); input never evaluated
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F005 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9a85521fafd1de7b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 162
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_rsa.py::TestRsaSigVer::test_rsa_pss_verify[SigVer-pss-ver-SHA-1-tc361_0]`
- **Message:** _pytest.outcomes.XFailed: SHA1_RSA_PKCS_PSS advertised but PSS params are not operational: Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID; expected one of: CKR_OK
- **Evidence:** Capability gap: SHA1_RSA_PKCS_PSS advertised but PSS params are not operational: Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID; expected one of: CKR_OK. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F006 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b4cd1222e320f24d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 20
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_rsa.py::TestRsaPss::test_rsa_pss_sign_verify[SigGen-pss-SHA2-256-tc37]`
- **Message:** _pytest.outcomes.XFailed: SHA256_RSA_PKCS_PSS advertised but sign/verify is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Capability gap: SHA256_RSA_PKCS_PSS advertised but sign/verify is not operational: CKR_MECHANISM_PARAM_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F007 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:001de3769ea30908#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_rsa.py::TestRsaPss::test_rsa_pss_sign_verify[SigGen-pss-SHA2-512-tc40]`
- **Message:** _pytest.outcomes.XFailed: SHA512_RSA_PKCS_PSS advertised but sign/verify is not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Capability gap: SHA512_RSA_PKCS_PSS advertised but sign/verify is not operational: CKR_MECHANISM_PARAM_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_ckr_codes.py` (1 findings)

#### F008 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ee51eaeabb526ead#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 5
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_codes.py::TestCKRMechanismErrors::test_ckr_mechanism_invalid`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_ckr_decrypt.py` (1 findings)

#### F009 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:006b0afc90b5925c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_decrypt.py::TestDecryptInitErrors::test_mechanism_invalid`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for CKR AES-CBC decrypt-param setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-256 key generation for CKR AES-CBC decrypt-param setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_ckr_derive.py` (2 findings)

#### F010 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:05a1b507868ea3eb#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_derive.py::TestDeriveKeyErrors::test_mechanism_invalid`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F011 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2b2782d8225aff5a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_derive.py::TestDeriveKeyErrors::test_key_type_inconsistent`
- **Message:** _pytest.outcomes.XFailed: C_DeriveKey(base_key_type_wrong_for_mechanism): rejected with CKR_MECHANISM_INVALID, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.14.5]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_DeriveKey(base_key_type_wrong_for_mechanism): rejected with CKR_MECHANISM_INVALID, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.14.5]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_dual.py` (1 findings)

#### F012 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7ce7e82c8a7e7a68#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_dual.py::TestOperationStateWrapper::test_encrypt_twice_succeeds`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for operation-state encrypt wrapper setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for operation-state encrypt wrapper setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_ckr_encrypt.py` (2 findings)

#### F013 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8a8dc8b2f08a25b5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 11
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_encrypt.py::TestEncryptInitErrors::test_mechanism_invalid`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for CKR AES-CBC parameter setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-256 key generation for CKR AES-CBC parameter setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F014 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:dbf102ea70b22b4d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_encrypt.py::TestEncryptInitErrors::test_key_type_inconsistent`
- **Message:** _pytest.outcomes.XFailed: C_EncryptInit(key_type_wrong_for_mechanism): rejected with CKR_MECHANISM_INVALID, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.8.1]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_EncryptInit(key_type_wrong_for_mechanism): rejected with CKR_MECHANISM_INVALID, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.8.1]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_fault_inject.py` (1 findings)

#### F015 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:29a73ea77a2e5fee#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_fault_inject.py::TestFaultInjection::test_inject_device_removed_on_encrypt`
- **Message:** _pytest.outcomes.XFailed: C_GenerateKey for fault-injected encrypt failed: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_GenerateKey for fault-injected encrypt failed: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK. Direction = reject-valid → functional gap (LOW).

### `test_ckr_keygen.py` (3 findings)

#### F016 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1626ad417a2fbb0d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyErrors::test_mechanism_invalid`
- **Message:** _pytest.outcomes.XFailed: C_GenerateKey(bogus_attribute_in_template): rejected with CKR_FUNCTION_NOT_SUPPORTED, spec prefers ['CKR_ATTRIBUTE_TYPE_INVALID'] [PKCS#11 v3.1 Sec.5.14.1]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_GenerateKey(bogus_attribute_in_template): rejected with CKR_FUNCTION_NOT_SUPPORTED, spec prefers ['CKR_ATTRIBUTE_TYPE_INVALID'] [PKCS#11 v3.1 Sec.5.14.1]. Direction = reject-valid → functional gap (LOW).

#### F017 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ad2038e68845d422#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyErrors::test_token_bool_overlong_length`
- **Message:** _pytest.outcomes.XFailed: C_GenerateKey with CK_ULONG-sized CKA_TOKEN boolean attribute: rejected with CKR_FUNCTION_NOT_SUPPORTED, expected ['CKR_ATTRIBUTE_TYPE_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONSISTENT', 'CKR_ARGUMENTS_BAD', 'CKR_FUNCTION_FAILED'
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_GenerateKey with CK_ULONG-sized CKA_TOKEN boolean attribute: rejected with CKR_FUNCTION_NOT_SUPPORTED, expected ['CKR_ATTRIBUTE_TYPE_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_TEMPLATE_INCOMPLETE', 'CKR_TEMPLATE_INCONSISTENT', 'CKR_ARG. Direction = reject-valid → functional gap (LOW).

#### F018 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:21af288a576f74eb#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyErrors::test_bad_key_size_zero`
- **Message:** _pytest.outcomes.XFailed: C_GenerateKey(invalid_key_size): rejected with CKR_FUNCTION_NOT_SUPPORTED, spec prefers ['CKR_ATTRIBUTE_VALUE_INVALID'] [PKCS#11 v3.1 Sec.5.14.1]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_GenerateKey(invalid_key_size): rejected with CKR_FUNCTION_NOT_SUPPORTED, spec prefers ['CKR_ATTRIBUTE_VALUE_INVALID'] [PKCS#11 v3.1 Sec.5.14.1]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_object.py` (1 findings)

#### F019 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:769f60b5581d0781#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_object.py::TestSetAttributeErrors::test_set_readonly_class`
- **Message:** Failed: C_SetAttributeValue claimed success and the read-only CKA_CLASS actually changed (self-contradiction) [PKCS#11 v3.1 Sec.5.7.6: CKA_CLASS is read-only]
- **Evidence:** tpm2: C_SetAttributeValue on read-only CKA_CLASS claimed success AND CKA_CLASS actually changed (self-contradiction). PKCS#11 v3.1 Sec.5.7.6: CKA_CLASS is read-only. policy attribute/permission self-contradiction.

### `test_ckr_priority.py` (1 findings)

#### F020 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4679579fe3b8f8c5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_priority.py::TestErrorPriority::test_destroyed_handle_with_wrong_mechanism`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_ckr_raw_args_bad.py` (2 findings)

#### F021 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0b23bd621b92fb1d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_args_bad.py::TestArgsBadNullPointers::test_generate_key_null_mechanism`
- **Message:** Failed: C_GenerateKey(NULL mech): subprocess failed with exit code 1
stdout: CKR:0x00000054
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name"
- **Evidence:** tpm2: C_GenerateKey(NULL mech) returned CKR_FUNCTION_NOT_SUPPORTED (0x54) instead of CKR_ARGUMENTS_BAD. Documented in module-issues.md 'Raw CKR NULL-mechanism findings'. Clean wrong-CKR for a NULL-argument probe (C_GenerateKey has no NULL-mech cancellation success path unlike C_EncryptInit).

#### F022 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:044e87189f8bb7fa#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_args_bad.py::TestArgsBadNullPointers::test_wrap_key_null_mechanism`
- **Message:** Failed: C_WrapKey(NULL mech): subprocess failed with exit code 1
stdout: CKR:0x00000054
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CK
- **Evidence:** tpm2: C_WrapKey(NULL mech) returned CKR_FUNCTION_NOT_SUPPORTED (0x54) instead of a specific argument, mechanism, or handle error. Documented in module-issues.md 'Raw CKR NULL-mechanism findings'. Clean wrong-CKR.

### `test_ckr_raw_attrs.py` (1 findings)

#### F023 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6943966545c6492c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_attrs.py::TestKeyFunctionNotPermitted::test_encrypt_not_permitted`
- **Message:** _pytest.outcomes.XFailed: C_GenerateKey for CKA_DECRYPT=False failed: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_GenerateKey for CKA_DECRYPT=False failed: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_ckr_raw_buffer.py` (3 findings)

#### F024 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f7af7b37262b7596`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestBufferTooSmall::test_encrypt_buffer_too_small`
- **Message:** _pytest.outcomes.XFailed: C_GenerateKey for AES encrypt failed: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

#### F025 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9f8dfa86a2bf93c1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestBufferTooSmall::test_digest_buffer_too_small`
- **Message:** _pytest.outcomes.XFailed: C_Digest returned CKR_OK for a 1-byte output buffer without writing past it (PKCS#11 §5.10.2 expects CKR_BUFFER_TOO_SMALL; clean return-code deviation, no buffer overflow)
- **Evidence:** Buffer-protocol deviation: C_Digest returned CKR_OK for a 1-byte output buffer without writing past it (PKCS#11 §5.10.2 expects CKR_BUFFER_TOO_SMALL; clean return-code deviation, no buffer overflow).

#### F026 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f1fd813760f0e7c0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestByteOutputBufferTooSmallGuards::test_get_operation_state_buffer_too_small_preserves_guard`
- **Message:** _pytest.outcomes.XFailed: C_GetOperationState is not saveable: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_GetOperationState is not saveable: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_ckr_raw_state.py` (1 findings)

#### F027 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:95e45379738f1389#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 5
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_state.py::TestOperationActive::test_double_encrypt_init`
- **Message:** _pytest.outcomes.XFailed: C_GenerateKey failed:CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_GenerateKey failed:CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_ckr_sign.py` (1 findings)

#### F028 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:acac9e9ada1380f7#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_sign.py::TestSignInitErrors::test_mechanism_invalid`
- **Message:** Failed: Should have rejected AES_ECB as signing mechanism
- **Evidence:** tpm2: C_SignInit accepted AES_ECB as a signing mechanism (should have rejected with CKR_MECHANISM_INVALID). AES_ECB is not a signing mechanism. Accept-invalid on mechanism validation.

### `test_ckr_spec_compliance.py` (1 findings)

#### F029 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e659cac459f211c7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 5
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_spec_compliance.py::TestCKRMechanismCompliance::test_sha256_as_encrypt_returns_mechanism_invalid`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_ckr_verify.py` (1 findings)

#### F030 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d11d2e30e14a55b2#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_verify.py::TestVerifyInitErrors::test_mechanism_invalid`
- **Message:** Failed: Should have rejected AES_ECB as verify mechanism
- **Evidence:** tpm2: C_VerifyInit accepted AES_ECB as a verify mechanism (should have rejected with CKR_MECHANISM_INVALID). AES_ECB is not a verification mechanism. Accept-invalid on mechanism validation.

### `test_ckr_wrong_key_type_hardening.py` (1 findings)

#### F031 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2d56b3a8e65ccf63#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_wrong_key_type_hardening.py::TestWrongAsymmetricKeyTypeContinuation::test_wrong_asymmetric_key_type_sign_continuation_no_crash`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_api_boundary.py` (3 findings)

#### F032 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:996f343b13e499ed#phase6`
- **Direction:** `CRASH` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_api_boundary.py::TestZeroLengthData::test_zero_length_data[encrypt-AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for decrypt zero-length CKM_AES_ECB crash probe setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: tpm2 AES_KEY_GEN rejects AES-256 keygen (CKR_FUNCTION_NOT_SUPPORTED) during zero-length CKM_AES_ECB crash-probe setup. Same root cause as sha1:4203722b70e0ed1f.

#### F033 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f1576cf1d305b286#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_api_boundary.py::TestZeroLengthData::test_zero_length_data[sign-RSA_PKCS]`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: tpm2 RSA_PKCS_KEY_PAIR_GEN returns CKR_ATTRIBUTE_VALUE_INVALID during zero-length sign-probe setup. RSA keygen not operational with this template.

#### F034 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8ce3bcb212eaa735#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_api_boundary.py::TestZeroLengthData::test_zero_length_data[sign-ECDSA]`
- **Message:** _pytest.outcomes.XFailed: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: tpm2 EC_KEY_PAIR_GEN returns CKR_ATTRIBUTE_VALUE_INVALID during zero-length sign-probe setup. EC keygen not operational with this template.

### `test_api_security.py` (1 findings)

#### F035 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:52233539da290dfe#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 10
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_api_security.py::TestWrapDecryptOracle::test_wrap_decrypt_combination_prevented`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_arithmetic_overflow.py` (3 findings)

#### F036 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:57a32caa62e50341`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestTemplateCountOverflowValidHandles::test_template_count_overflow_with_valid_object_handle[get_attribute_value-ulong_max]`
- **Message:** Failed: C_GetAttributeValue(valid object, template_count=0x100000000): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F037 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:4f77e20c9dd17cad`
- **Direction:** `CRASH` · **Outcome:** `xfail` · **Tests covered:** 12
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestDataLengthOverflow::test_data_length_overflow[encrypt-ulong_max]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for CKM_AES_CBC parameter-length overflow crash probe setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F038 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:ed830ff3eaad5259`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestPssSaltLengthOverflow::test_pss_salt_length_overflow[ulong_max]`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_crypto_weakness.py` (1 findings)

#### F039 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6fa1a8e0e931f6b3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_crypto_weakness.py::TestDeprecatedMechanismOperation::test_deprecated_sign_operation[SHA1_RSA_PKCS]`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_cve_regression.py` (1 findings)

#### F040 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:593281de75b0c097#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_cve_regression.py::TestSessionObjectsAfterLogout::test_session_objects_after_logout`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for session object after logout is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for session object after logout is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_error_path_rsa.py` (1 findings)

#### F041 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ca3e5bf5e190e66c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_error_path_rsa.py::TestRsaPkcsDecryptErrorPaths::test_rsa_pkcs_decrypt_random_ciphertext`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_ffi_length_boundary.py` (10 findings)

#### F042 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:05d2e3d7c40c12cc`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_digest_isize_boundary[isize_max]`
- **Message:** Failed: C_Digest(SHA256, ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F043 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:a5f42cb3b2aa9ea4`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_digest_isize_boundary[isize_max_plus_1]`
- **Message:** Failed: C_Digest(SHA256, ulDataLen=0x8000000000000000): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F044 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:333612559a8e7e0f`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[digest_update-isize_max]`
- **Message:** Failed: C_DigestUpdate(ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_DigestUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F045 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:14d61e2dc97336f8`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[digest_update-isize_max_plus_1]`
- **Message:** Failed: C_DigestUpdate(ulDataLen=0x8000000000000000): module crashed with signal 11
stdout: TARGET:C_DigestUpdate
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F046 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:bdeacd6d3fae6067`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRandomIsizeLength::test_generate_random_isize_length_preserves_guard[isize_max]`
- **Message:** Failed: C_GenerateRandom(ulRandomLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_GenerateRandom
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F047 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:8243cb6bceb64c76`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRandomIsizeLength::test_generate_random_isize_length_preserves_guard[isize_max_plus_1]`
- **Message:** Failed: C_GenerateRandom(ulRandomLen=0x8000000000000000): module crashed with signal 11
stdout: TARGET:C_GenerateRandom
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F048 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:db825d138cb3dd28`
- **Direction:** `CRASH` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_encrypt_isize_boundary[isize_max]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for C_Decrypt isize-boundary crash probe setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F049 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:d21a325d421fdc6c`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRsaPssSaltLengthBoundary::test_rsa_pss_salt_length_boundary[isize_max]`
- **Message:** _pytest.outcomes.XFailed: RSA keypair generation rejected: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F050 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:86693b5f9c8ede76`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestMechanismNullInnerParams::test_ecdh_null_public_data`
- **Message:** _pytest.outcomes.XFailed: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F051 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:1c553d3d63e4c69a`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestMechanismNullInnerParams::test_oaep_null_source_data`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_ffi_null_pointer.py` (1 findings)

#### F052 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4203722b70e0ed1f#phase6`
- **Direction:** `CRASH` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestNullDataUpdate::test_null_data_update[C_EncryptUpdate]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for C_DecryptUpdate NULL-data crash probe setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: tpm2 AES_KEY_GEN rejects AES-256 keygen with CKR_FUNCTION_NOT_SUPPORTED during crash-probe setup. The CRASH direction label is misleading — setup fails before the NULL-pointer probe can run. Real issue is missing AES-256 keygen on tpm2.

### `test_handle_reuse.py` (1 findings)

#### F053 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5c8160e92a8d71d5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 5
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_handle_reuse.py::TestHandleReuseAfterDestroy::test_get_attribute_after_destroy`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for handle-reuse setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for handle-reuse setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_nonce_quality.py` (1 findings)

#### F054 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:56555785b30d0fb5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_nonce_quality.py::TestECDSANonceReuse::test_nonce_reuse_p256`
- **Message:** _pytest.outcomes.XFailed: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_padding_oracle.py` (2 findings)

#### F055 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cd94bf48af878abe#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 5
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_padding_oracle.py::TestRSAPaddingOracle::test_pkcs1v15_error_uniformity`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F056 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4708ba7aef593771#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_padding_oracle.py::TestAESPaddingOracle::test_cbc_pad_error_uniformity`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_parameter_validation.py` (2 findings)

#### F057 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b24ab62dfb2270c9#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestRsaExponent::test_rsa_weak_public_exponent[e=1]`
- **Message:** _pytest.outcomes.XFailed: RSA keygen with cryptographically invalid exponent e=1: rejected with CKR_GENERAL_ERROR, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RSA keygen with cryptographically invalid exponent e=1: rejected with CKR_GENERAL_ERROR, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_. Direction = reject-valid → functional gap (LOW).

#### F058 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9b82090fab14a33e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestCbcIvAllZeros::test_cbc_iv_all_zeros`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_secret_key_value_len.py` (3 findings)

#### F059 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:31c4cc6aa2509129`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestExistingSecretKeyValueLen::test_set_secret_key_oversized_value_len_does_not_crash`
- **Message:** Failed: C_SetAttributeValue(secret key, CKA_VALUE_LEN=0xffffffffffffffff): subprocess failed with exit code 1
stdout: TARGET_RV:0x00000000
VALUE_LEN_RV:0x00000000
VALUE_LEN_VALUE:18446744073709551615
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F060 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:aedab0c3fc708e93`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestDigestKeySecretKeyValueLen::test_digest_key_after_oversized_value_len_import_does_not_crash`
- **Message:** Failed: C_DigestKey(secret key imported with CKA_VALUE_LEN=0xffffffffffffffff): subprocess failed with exit code 1
stdout: VALUE_LEN_RV:0x00000000
VALUE_LEN_VALUE:18446744073709551615
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","me
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F061 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e1db7844f5e42be1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestUnwrapSecretKeyValueLen::test_aes_ecb_unwrap_oversized_value_len_does_not_crash`
- **Message:** _pytest.outcomes.XFailed: AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_tookan.py` (1 findings)

#### F062 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f6985a300eb108d0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_tookan.py::TestSensitivePreservation::test_sensitive_preserved_on_copy`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_access.py` (1 findings)

#### F063 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:154fa6239bc0a7df#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_access.py::TestLoginStates::test_public_session_no_private_keys`
- **Message:** assert 7 == 0
 +  where 7 = len([13, 14, 15, 17, 19, 20, ...])
- **Evidence:** tpm2: 7 CKA_CLASS=CKO_PRIVATE_KEY objects found via C_FindObjects in a public (no-login) RO session. PKCS#11 requires private objects to be invisible until C_Login. Documented in module-issues.md under test_session_state_machine::test_open_session_is_private. Access-control break.

### `test_access_control.py` (1 findings)

#### F064 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8d97326d2dc263f6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_access_control.py::TestPrivateAttribute::test_non_private_object_visible_without_login`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **Evidence:** tpm2: C_CreateObject for a CKA_PRIVATE=False data object (test_non_private_object_visible_without_login) returns CKR_ATTRIBUTE_VALUE_INVALID. TPM design constraint: TPM-backed objects are inherently private; creating CKA_PRIVATE=False objects is rejected. Reject-valid on the public-object template.

### `test_access_levels.py` (1 findings)

#### F065 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c95befca68bf0c29#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 11
- **Example nodeid:** `src/pkcs11_check/testcases/test_access_levels.py::TestPublicSessionVisibility::test_public_cannot_see_private_objects`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_aead.py` (1 findings)

#### F066 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:050c55e55a784854#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_aead.py::TestAESGCMProperties::test_gcm_different_nonces_different_ct`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_attribute_enforcement.py` (1 findings)

#### F067 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b40b09362fbb60b1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 11
- **Example nodeid:** `src/pkcs11_check/testcases/test_attribute_enforcement.py::TestCopyableOneWay::test_copyable_false_cannot_be_set_true`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for CKA_COPYABLE=False setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-256 key generation for CKA_COPYABLE=False setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_attribute_fuzz.py` (1 findings)

#### F068 [LOW/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:c93c2db23a55511c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_attribute_fuzz.py::TestDuplicateAttributes::test_create_key_normal`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **Evidence:** tpm2: test_create_key_normal calls gen_aes_key directly (no xfail wrapper) and hard-fails on CKR_FUNCTION_NOT_SUPPORTED. Same documented no-symmetric-keygen-surface deviation. Test should use the shared advertised-keygen classifier.

### `test_attribute_invariants.py` (1 findings)

#### F069 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9140487670999362#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_attribute_invariants.py::TestDerivedAttributeInvariants::test_never_extractable_when_created_non_extractable`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_authenticated_wrap.py` (1 findings)

#### F070 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fafcb37c90412cd9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_authenticated_wrap.py::TestAuthenticatedWrap::test_authenticated_wrap_requires_v32`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_benchmark.py` (1 findings)

#### F071 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:35dc585e155fbc4c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_benchmark.py::test_bench_aes256_cbc_encrypt`
- **Message:** _pytest.outcomes.XFailed: CKM_AES_KEY_GEN advertised but AES-256 keygen rejected: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Keygen capability gap: CKM_AES_KEY_GEN advertised but AES-256 keygen rejected: CKR_FUNCTION_NOT_SUPPORTED.

### `test_buffers.py` (1 findings)

#### F072 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:856187d8b1bc1416#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 5
- **Example nodeid:** `src/pkcs11_check/testcases/test_buffers.py::TestEncryptBufferSizes::test_single_block`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_cctv_rfc6979.py` (1 findings)

#### F073 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d4c0356e6f94a320`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_cctv_rfc6979.py::test_rfc6979_ecdsa_verify`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA256:key-import: advertised but not operational (P-256 private-key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_concurrent_sessions.py` (1 findings)

#### F074 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e98cea2548ff2f35#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 5
- **Example nodeid:** `src/pkcs11_check/testcases/test_concurrent_sessions.py::TestConcurrentSessions::test_two_sessions_see_same_token_object`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_crossverify.py` (1 findings)

#### F075 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f701de29da7eb461#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_crossverify.py::TestRSACrossVerify::test_rsa_4096_sign`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_data_objects.py` (1 findings)

#### F076 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7dafb8f82d59a61f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_data_objects.py::TestDataObjectCreate::test_create_data_object_empty_value`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **Evidence:** tpm2: C_CreateObject for a data object with empty CKA_VALUE (test_create_data_object_empty_value) returns CKR_ATTRIBUTE_VALUE_INVALID. Reject-valid — empty-value data objects are spec-permitted; tpm2 rejects the template.

### `test_digest.py` (1 findings)

#### F077 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4b207cc5c93cd279#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_digest.py::TestDigestKey::test_digest_key_matches_hashlib`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 setup for C_DigestKey is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 setup for C_DigestKey is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_duplicate_labels.py` (1 findings)

#### F078 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4c1d2810cfd9a2d9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_duplicate_labels.py::TestDuplicateLabels::test_two_keys_same_label`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_ec_curves.py` (1 findings)

#### F079 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5c506370c22029e7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_ec_curves.py::TestECDSACrossVerify::test_ecdsa_sign_p11_verify_crypto[P-224]`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_GENERAL_ERROR; expected one of: CKR_OK
- **Evidence:** tpm2: ECDSA sign on P-224 returns CKR_GENERAL_ERROR ('Cannot figure out hashing algorithm for signature of len: 28'). TPM hardware constraint: P-224 is not in the TPM — only P-256 is supported. Should return CKR_CURVE_NOT_SUPPORTED.

### `test_ec_import_export.py` (1 findings)

#### F080 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:91303caeceb02f0d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_ec_import_export.py::TestECPublicKeyImport::test_generate_export_import_verify[secp521r1]`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_HOST_MEMORY; expected one of: CKR_OK
- **Evidence:** tpm2: EC sign on secp521r1 returns CKR_HOST_MEMORY with OpenSSL ASN.1 'too long' error. TPM hardware constraint: P-521 is not in the TPM — only P-256 ECDSA is supported. Should return CKR_CURVE_NOT_SUPPORTED, not CKR_HOST_MEMORY.

### `test_encrypt.py` (2 findings)

#### F081 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:217c23d690202a52#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 11
- **Example nodeid:** `src/pkcs11_check/testcases/test_encrypt.py::TestAESEncryption::test_aes_generate_key`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F082 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:eb1f1142b111f1ed#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_encrypt.py::TestRSAEncryption::test_rsa_pkcs_roundtrip`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_errors.py` (2 findings)

#### F083 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:40d66a92266a4197#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 7
- **Example nodeid:** `src/pkcs11_check/testcases/test_errors.py::TestInvalidOperations::test_invalid_mechanism_param`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for empty-data encryption is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for empty-data encryption is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F084 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:edb9ef6150134928#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_errors.py::TestInvalidOperations::test_decrypt_garbage`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation for decrypt-garbage check is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation for decrypt-garbage check is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_fuzz.py` (3 findings)

#### F085 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4b5ff5646df862ae#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_fuzz.py::TestAESFuzz::test_ecb_roundtrip`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but fuzz AES setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
Falsifying example: test_ecb_ciphertext_differs_from_plaintext(
    self=<pkcs11_check.testcases.test_fuzz.TestAESFuzz object at 0x7fb873e27360>,
    p11_raw_session=RawSession(raw=<pkc
- **Evidence:** Capability gap: AES_KEY_GEN advertised but fuzz AES setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
Falsifying example: test_ecb_ciphertext_differs_from_plaintext(
    self=<pkcs11_check.testcases.test_fuzz.TestAESFuzz object at 0x7fb873e27360>,
    p. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F086 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9a5bbf609050b6e0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_fuzz.py::TestHMACFuzz::test_hmac_sha256_cross_verify`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC advertised but fuzz sign is not operational: CKR_GENERAL_ERROR
Falsifying example: test_hmac_deterministic(
    self=<pkcs11_check.testcases.test_fuzz.TestHMACFuzz object at 0x7fb873f0f390>,
    p11_raw_session=RawSession(raw=<pkcs11_check.raw.api.RawPKCS11 obje
- **Evidence:** Capability gap: SHA256_HMAC advertised but fuzz sign is not operational: CKR_GENERAL_ERROR
Falsifying example: test_hmac_deterministic(
    self=<pkcs11_check.testcases.test_fuzz.TestHMACFuzz object at 0x7fb873f0f390>,
    p11_raw_session=RawSession(raw=<p. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F087 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e95cb6bf800301e1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_fuzz.py::TestECDSAFuzz::test_ecdsa_sign_verify_roundtrip`
- **Message:** _pytest.outcomes.XFailed: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
Falsifying example: test_ecdsa_sign_verify_roundtrip(
    self=<pkcs11_check.testcases.test_fuzz.TestECDSAFuzz object at 0x7fb873f0f4d0>,
    p11_raw_session=RawSession(raw=<pk
- **Evidence:** Capability gap: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
Falsifying example: test_ecdsa_sign_verify_roundtrip(
    self=<pkcs11_check.testcases.test_fuzz.TestECDSAFuzz object at 0x7fb873f0f4d0>,
    . Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_generic_secret.py` (2 findings)

#### F088 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:26a2b90e0db6d417#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_generic_secret.py::TestGenericSecretHMAC::test_hmac_with_imported_generic_secret`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC advertised but sign is not operational: CKR_GENERAL_ERROR
- **Evidence:** Capability gap: SHA256_HMAC advertised but sign is not operational: CKR_GENERAL_ERROR. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F089 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2760e0dedeafb4f1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_generic_secret.py::TestGenericSecretHMAC::test_hmac_sha512_crossverify`
- **Message:** _pytest.outcomes.XFailed: SHA512_HMAC advertised but sign is not operational: CKR_GENERAL_ERROR
- **Evidence:** Capability gap: SHA512_HMAC advertised but sign is not operational: CKR_GENERAL_ERROR. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_interface.py` (1 findings)

#### F090 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8d536a7b792db697#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_interface.py::TestInterfaceV30::test_v30_encrypt_decrypt_aes`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_kdf.py` (3 findings)

#### F091 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:bfcf75391c0c3276#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_kdf.py::TestECDHDerive::test_ecdh_keypair_independence`
- **Message:** _pytest.outcomes.XFailed: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F092 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2bb7fdbfab250cc4#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_kdf.py::TestKeyDeriveSoftware::test_hmac_as_kdf`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC advertised but sign is not operational: CKR_GENERAL_ERROR
- **Evidence:** Capability gap: SHA256_HMAC advertised but sign is not operational: CKR_GENERAL_ERROR. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F093 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:739b4f3710a08198#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_kdf.py::TestKeyDeriveSoftware::test_hmac_sha512_as_kdf`
- **Message:** _pytest.outcomes.XFailed: SHA512_HMAC advertised but sign is not operational: CKR_GENERAL_ERROR
- **Evidence:** Capability gap: SHA512_HMAC advertised but sign is not operational: CKR_GENERAL_ERROR. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_key_flags.py` (1 findings)

#### F094 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2b11fdeee475c112#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 14
- **Example nodeid:** `src/pkcs11_check/testcases/test_key_flags.py::TestNeverExtractable::test_generated_non_extractable_is_never_extractable`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_key_lifecycle.py` (1 findings)

#### F095 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fc5f4112245c1d90#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_key_lifecycle.py::TestECKeyLifecycle::test_ec_export_import_verify`
- **Message:** AssertionError: C_GenerateKeyPair failed: CKR_ATTRIBUTE_VALUE_INVALID
assert <CKR_ATTRIBUTE_VALUE_INVALID: 0x00000013> == <CKR_OK: 0x00000000>
- **Evidence:** tpm2: C_GenerateKeyPair for an EC keypair (test_ec_export_import_verify) returns CKR_ATTRIBUTE_VALUE_INVALID ('Expected attr 0x1 to be 0, got 1'). Same keygen-not-operational deviation class as the RSA keygen xfail; the EC lifecycle test uses a raw assert instead of gen_ec_keypair_or_xfail so it surfaces as a hard fail rather than xfail.

### `test_key_sizes.py` (2 findings)

#### F096 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f2c8c27c3d3eca9a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_key_sizes.py::TestAESKeySizes::test_aes_generate[128]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for key-size coverage is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for key-size coverage is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F097 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0497ec2ceecaa386#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_key_sizes.py::TestRSAKeySizes::test_rsa_generate[4096]`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_key_usage_policy.py` (2 findings)

#### F098 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:25c72721f610716a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 5
- **Example nodeid:** `src/pkcs11_check/testcases/test_key_usage_policy.py::TestAESKeyUsagePolicy::test_encrypt_only_key_cannot_decrypt`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F099 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2e5d3705f2ba3437#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_key_usage_policy.py::TestRSAKeyUsagePolicy::test_sign_only_rsa_cannot_encrypt`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_GENERAL_ERROR
- **Evidence:** Capability gap: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_GENERAL_ERROR. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_keymgmt.py` (1 findings)

#### F100 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0e6c045e63bc3e7c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_keymgmt.py::TestKeyCopy::test_copy_preserves_attributes`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for key-management setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for key-management setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_large_objects.py` (1 findings)

#### F101 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:88ac7a2052ef63f3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_large_objects.py::TestLargeEncryption::test_encrypt_64kb_aes_ecb`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-256 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_mech_attribute.py` (1 findings)

#### F102 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:237bc92b6c722426#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_attribute.py::TestKeyAttributes::test_key_type_matches_template[AES_KEY_GEN]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_GEN keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_mech_encrypt.py` (10 findings)

#### F103 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3b55e652640d0605`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptKAT::test_kat_vector[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC:encrypt: advertised but not operational (CKR_GENERAL_ERROR)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F104 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3d643015399d583b`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptKAT::test_kat_vector[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD:encrypt: advertised but not operational (CKR_GENERAL_ERROR)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F105 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f72c92035e79ec1a`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptKAT::test_kat_vector[AES_CFB128]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB128:encrypt: advertised but not operational (CKR_GENERAL_ERROR)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F106 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:273a7124b76e9c16`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptKAT::test_kat_vector[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR:encrypt: advertised but not operational (CKR_GENERAL_ERROR)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F107 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:83d0bc559b31063f`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptKAT::test_kat_vector[AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB:encrypt: advertised but not operational (CKR_GENERAL_ERROR)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F108 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:28d1e46d829d3342#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F109 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2ba87cfb9751085b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC_PAD keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F110 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5edd866469fe8f8a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[AES_CFB128]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB128 keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB128 keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F111 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1287623a995090b9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F112 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:97e3ad3db37b7eac#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_ECB keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_mech_keygen.py` (1 findings)

#### F113 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:89261fcf0fc7bc16#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_keygen.py::TestMechKeygen::test_generate_key[AES_KEY_GEN]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_GEN keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_mech_lifecycle.py` (3 findings)

#### F114 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c5c56c526cf50a19#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_lifecycle.py::TestDigestThenEncrypt::test_sha256_digest_then_aes_ecb_encrypt`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for batch AES lifecycle setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for batch AES lifecycle setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F115 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:bb1ea219ebdf0dd5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_lifecycle.py::TestECDHDerivedKeyUse::test_ecdh_derive_and_use`
- **Message:** _pytest.outcomes.XFailed: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F116 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9685c2d2252c4ac9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_lifecycle.py::TestRSAOAEPWrapLifecycle::test_rsa_oaep_wrap_aes_roundtrip`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_mech_multipart.py` (5 findings)

#### F117 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2e31f82333308cf0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F118 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9f04711662ad1c3b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC_PAD keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F119 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4900a53fcb5af215#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[AES_CFB128]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB128 keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB128 keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F120 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8c69ed41544b27ed#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F121 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5630d4430adfbf8a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_ECB keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_mech_negative.py` (23 findings)

#### F122 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:44344e4e6c6f6d93#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F123 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fe0442ec1c14bc35#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC_PAD keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F124 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:150638b003d3cb87#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CFB128]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB128 keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB128 keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F125 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:08791695d3db3323#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F126 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1b7086feff2aa8ba#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA256_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA256_RSA_PKCS_PSS keypair rejected at runtime: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** RSA padding hash-variant gap: SHA256_RSA_PKCS_PSS keypair rejected at runtime: CKR_ATTRIBUTE_VALUE_INVALID. Module only supports subset of RFC 8017 hash/MGF combinations.

#### F127 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5950d0e7c412dbf8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA384_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA384_RSA_PKCS_PSS keypair rejected at runtime: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** RSA padding hash-variant gap: SHA384_RSA_PKCS_PSS keypair rejected at runtime: CKR_ATTRIBUTE_VALUE_INVALID. Module only supports subset of RFC 8017 hash/MGF combinations.

#### F128 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b666a093d56f066f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_sign_missing_required_param[SHA512_RSA_PKCS_PSS]`
- **Message:** _pytest.outcomes.XFailed: SHA512_RSA_PKCS_PSS keypair rejected at runtime: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** RSA padding hash-variant gap: SHA512_RSA_PKCS_PSS keypair rejected at runtime: CKR_ATTRIBUTE_VALUE_INVALID. Module only supports subset of RFC 8017 hash/MGF combinations.

#### F129 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9bf2a7eaea0d0d2d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_rsa_pkcs_with_aes_key_rejected`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for decrypt-permission negative test setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-256 key generation for decrypt-permission negative test setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F130 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4e72a1215e21c6ec#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_encrypt_without_flag[AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_ECB keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F131 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ef5f1c087fb6bd66#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA256_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA256_HMAC keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F132 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ff6fb886c30844fd#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA384_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA384_HMAC keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA384_HMAC keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F133 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3ea47907a3a12a27#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA512_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA512_HMAC keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA512_HMAC keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F134 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7c2b985fbc1b7943#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestMissingPermission::test_registry_sign_without_flag[SHA_1_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA_1_HMAC keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SHA_1_HMAC keygen rejected at runtime: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

#### F135 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e447cb1f7b815e86#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_encrypt_wrong_key_type[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC encrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC encrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F136 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a47015e3ebba1401#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_encrypt_wrong_key_type[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD encrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC_PAD encrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F137 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:15bae8d27c028514#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_encrypt_wrong_key_type[AES_CFB128]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB128 encrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB128 encrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F138 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a8c917cdabec197e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_encrypt_wrong_key_type[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR encrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR encrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F139 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7304deff34528a50#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_encrypt_wrong_key_type[AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB encrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_ECB encrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F140 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d5790bb07b2fb3a7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_decrypt_wrong_key_type[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC decrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC decrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F141 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a6128a1378feca7e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_decrypt_wrong_key_type[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD decrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC_PAD decrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F142 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e5cdb28ffb3f7157#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_decrypt_wrong_key_type[AES_CFB128]`
- **Message:** _pytest.outcomes.XFailed: AES_CFB128 decrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CFB128 decrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F143 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4a8aac326107a9f4#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_decrypt_wrong_key_type[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR decrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR decrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F144 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:90fa2b53021d8e3e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_decrypt_wrong_key_type[AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB decrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_ECB decrypt with wrong key type: rejected with CKR_GENERAL_ERROR, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

### `test_mech_sign.py` (12 findings)

#### F145 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a945a68b35b6b42f`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[SHA256_RSA_PKCS]`
- **Message:** _pytest.outcomes.XFailed: SHA256_RSA_PKCS keypair rejected at runtime: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F146 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:229121043fff8ac7`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 5
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[SHA384_RSA_PKCS]`
- **Message:** _pytest.outcomes.XFailed: SHA384_RSA_PKCS keypair rejected at runtime: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F147 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f18d6aba1e2228d9`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 5
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[SHA512_RSA_PKCS]`
- **Message:** _pytest.outcomes.XFailed: SHA512_RSA_PKCS keypair rejected at runtime: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F148 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a06006c881eab05d`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[ECDSA_SHA1]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA1:key-import: advertised but not operational (EC private key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F149 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:742ad1da2afdd576`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[ECDSA_SHA256]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA256:key-import: advertised but not operational (EC private key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F150 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9afcfd9f35cf15a9`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[ECDSA_SHA384]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA384:key-import: advertised but not operational (EC private key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F151 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d016877e7d08fc3b`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[ECDSA_SHA512]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_SHA512:key-import: advertised but not operational (EC private key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F152 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f1c9093c5c31ac24`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[SHA1_RSA_PKCS]`
- **Message:** _pytest.outcomes.XFailed: SHA1_RSA_PKCS:key-import: advertised but not operational (RSA private key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F153 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:340a34dc60e3e6aa`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[SHA256_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC:kat-sign: advertised but not operational (CKR_GENERAL_ERROR)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F154 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0e23759b4d697930`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[SHA384_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA384_HMAC:kat-sign: advertised but not operational (CKR_GENERAL_ERROR)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F155 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:26aa5436c2a294bc`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[SHA512_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA512_HMAC:kat-sign: advertised but not operational (CKR_GENERAL_ERROR)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F156 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:159c3c9910428ba0`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[SHA_1_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA_1_HMAC:kat-sign: advertised but not operational (CKR_GENERAL_ERROR)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_sign_recover.py` (1 findings)

#### F157 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:703651a54316d34d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign_recover.py::TestSignRecover::test_rsa_x509_sign_recover_roundtrip`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_mech_state.py` (1 findings)

#### F158 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:65fc1e44d13587e5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_state.py::TestSignState::test_sign_single_part_output_call_terminates`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_GENERAL_ERROR; expected one of: CKR_OK
- **Evidence:** tpm2: C_Sign (single-part output call) returned CKR_GENERAL_ERROR on a key that lacks CKA_ALLOWED_MECHANISMS. CKR_GENERAL_ERROR is a non-specific catch-all; the module should return a concrete error. Sign-path operational deviation surfaced as a generic error.

### `test_mechanism_fuzz.py` (1 findings)

#### F159 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d4a60bf9200146f7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 10
- **Example nodeid:** `src/pkcs11_check/testcases/test_mechanism_fuzz.py::TestAESParameterFuzz::test_aes_cbc_bad_iv[empty]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-256 key generation for AES-CBC parameter-fuzz setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-256 key generation for AES-CBC parameter-fuzz setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_metamorphic.py` (1 findings)

#### F160 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cc89c050b311bff9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 8
- **Example nodeid:** `src/pkcs11_check/testcases/test_metamorphic.py::TestRoundTripInvariants::test_aes_ecb_roundtrip[128]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for AES-ECB metamorphic roundtrip is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for AES-ECB metamorphic roundtrip is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_multipart.py` (1 findings)

#### F161 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b829f46d5a8d0fb9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_multipart.py::TestMultiPartEncrypt::test_encrypt_16kb`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for legacy multipart smoke is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for legacy multipart smoke is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_multipart_streaming.py` (3 findings)

#### F162 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:56a3a73ce59418e6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 7
- **Example nodeid:** `src/pkcs11_check/testcases/test_multipart_streaming.py::TestMultipartEncrypt::test_aes_ecb_multiblock_roundtrip[1]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but key generation for AES-CBC streaming is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but key generation for AES-CBC streaming is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F163 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5549869fb83b0d90#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_multipart_streaming.py::TestMultipartEncrypt::test_aes_ecb_crossverify_large[16]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB advertised but encrypt is not operational: CKR_GENERAL_ERROR
- **Evidence:** Capability gap: AES_ECB advertised but encrypt is not operational: CKR_GENERAL_ERROR. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F164 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:19b9954080d8530e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_multipart_streaming.py::TestMultipartSign::test_hmac_large_data_crossverify`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC advertised but sign is not operational: CKR_BUFFER_TOO_SMALL
- **Evidence:** Capability gap: SHA256_HMAC advertised but sign is not operational: CKR_BUFFER_TOO_SMALL. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_object.py` (1 findings)

#### F165 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c885a4983dd250da#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_object.py::TestSessionObjects::test_create_secret_key_with_label`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for object attribute readback setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for object attribute readback setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_object_search_patterns.py` (1 findings)

#### F166 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9fbb8d9c398df9da#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_object_search_patterns.py::TestSearchByID::test_find_key_by_id`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for multi-attribute object search is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for multi-attribute object search is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_object_size.py` (2 findings)

#### F167 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:24f46505ecf176a0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_object_size.py::TestObjectSize::test_aes_key_has_size`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F168 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8250bd2d75861c11#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_object_size.py::TestObjectSize::test_data_object_size_scales`
- **Message:** _pytest.outcomes.XFailed: C_GetObjectSize rejected a valid object handle: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_GetObjectSize rejected a valid object handle: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_operation_termination.py` (3 findings)

#### F169 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4a9dac7116227bda#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_c_verify_terminates_after_rejected_rsa_signature`
- **Message:** Failed: RSA: C_Verify(empty) returned CKR_ARGUMENTS_BAD but left the verify operation active (next C_VerifyInit -> CKR_OPERATION_ACTIVE) -- the spec requires C_Verify to ALWAYS terminate the active verification operation: success claimed then contradicted (self-contradiction)
- **Evidence:** tpm2: C_Verify(empty RSA sig) returned CKR_ARGUMENTS_BAD but left the verify operation active — next C_VerifyInit returns CKR_OPERATION_ACTIVE. PKCS#11 v3.1 requires C_Verify to ALWAYS terminate the active verification operation. lifecycle self-contradiction. Test source explicitly names tpm2-pkcs11 as the offender for empty-sig CKR_ARGUMENTS_BAD.

#### F170 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6f26a605e476e892#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_c_verify_terminates_after_rejected_ecdsa_signature`
- **Message:** Failed: ECDSA: C_Verify(empty) returned CKR_ARGUMENTS_BAD but left the verify operation active (next C_VerifyInit -> CKR_OPERATION_ACTIVE) -- the spec requires C_Verify to ALWAYS terminate the active verification operation: success claimed then contradicted (self-contradiction)
- **Evidence:** tpm2: C_Verify(empty ECDSA sig) returned CKR_ARGUMENTS_BAD but left the verify operation active (CKR_OPERATION_ACTIVE on next init). Same lifecycle self-contradiction as the RSA variant.

#### F171 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:47b90dcd8f21183f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_c_verify_final_terminates_after_rejected_signature`
- **Message:** Failed: RSA: C_VerifyFinal(empty) returned CKR_ARGUMENTS_BAD but left the verify operation active (next C_VerifyInit -> CKR_OPERATION_ACTIVE) -- the spec requires C_VerifyFinal to ALWAYS terminate the active verification operation: success claimed then contradicted (self-contradiction)
- **Evidence:** tpm2: C_VerifyFinal(empty) returned CKR_ARGUMENTS_BAD but left the verify operation active. PKCS#11 requires C_VerifyFinal to always terminate. lifecycle self-contradiction.

### `test_remaining_gaps.py` (1 findings)

#### F172 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e6d88b2e2e990f21#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_remaining_gaps.py::TestTemplateConstraintAttributes::test_wrap_template_attribute_readable`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for CKA_DERIVE_TEMPLATE readback setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for CKA_DERIVE_TEMPLATE readback setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_resource.py` (1 findings)

#### F173 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:330d91ee54011b74#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_resource.py::TestMemoryLeaks::test_key_generation_no_leak`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for resource/stress setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for resource/stress setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_ro_session.py` (1 findings)

#### F174 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:273b90c4aac987ad#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_ro_session.py::TestROSessionOperations::test_verify_in_ro_session`
- **Message:** assert False is True
- **Evidence:** tpm2: verify in a read-only session returns False (assert result is True fails). A verify (read operation) should succeed in an RO session. Reject-valid — likely related to the documented session/object visibility deviation.

### `test_rsa_key_import.py` (1 findings)

#### F175 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9afac0baed18731a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_rsa_key_import.py::TestRSAPrivateKeyImport::test_import_rsa_private_key`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **Evidence:** tpm2: C_CreateObject for an RSA private key (import) returns CKR_ATTRIBUTE_VALUE_INVALID — 'Can only create RSA Public key objects or data objects'. TPM design constraint: the TPM must generate private keys on-device; externally-generated RSA private keys cannot be imported through the standard path. Reject-valid on private-key import.

### `test_rsa_key_wrapping.py` (1 findings)

#### F176 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d94f40d9098b02fa#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_rsa_key_wrapping.py::TestRSAPKCSWrap::test_wrap_unwrap_aes128`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_rsa_oaep.py` (1 findings)

#### F177 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1f440535c6c048c3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 9
- **Example nodeid:** `src/pkcs11_check/testcases/test_rsa_oaep.py::TestRSAOAEPRoundtrip::test_oaep_encrypt_decrypt`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_search.py` (1 findings)

#### F178 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:76f1e01dfd8b944e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_search.py::TestObjectSearch::test_find_by_label`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for object search by class is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for object search by class is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_sensitivity.py` (1 findings)

#### F179 [CRITICAL/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:330d6f7e694f71a9#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_sensitivity.py::TestSensitiveKeyValue::test_sensitive_value_not_copied_on_rejected_get_attribute`
- **Message:** Failed: raw C_GetAttributeValue copied CKA_VALUE bytes for a CKA_SENSITIVE=True AES key: claimed the protection then violated it (self-contradiction)
- **Evidence:** tpm2: raw C_GetAttributeValue copied CKA_VALUE bytes for an imported CKA_SENSITIVE=True AES key (test_sensitivity). Import via C_CreateObject succeeded and CKA_SENSITIVE read back True, then C_GetAttributeValue(CKA_VALUE) returned CKR_OK and copied the secret into the caller buffer. policy self-contradiction: claimed the protection then violated it. Sensitive key material leak is a crypto-correctness break.

### `test_session_edge_cases.py` (2 findings)

#### F180 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8cfc121c489dc6f6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_session_edge_cases.py::TestCloseAllSessions::test_close_all_sessions`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F181 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1184c66eabdd7f1b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_session_edge_cases.py::TestStaleSessionHandles::test_generate_key_after_close`
- **Message:** _pytest.outcomes.XFailed: C_GenerateKey on closed session: rejected with CKR_FUNCTION_NOT_SUPPORTED, expected ['CKR_SESSION_HANDLE_INVALID', 'CKR_SESSION_CLOSED']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_GenerateKey on closed session: rejected with CKR_FUNCTION_NOT_SUPPORTED, expected ['CKR_SESSION_HANDLE_INVALID', 'CKR_SESSION_CLOSED']. Direction = reject-valid → functional gap (LOW).

### `test_session_exhaustion.py` (1 findings)

#### F182 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1ee7c17d35c9dddd#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_session_exhaustion.py::TestSessionExhaustion::test_open_many_sessions`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_session_info.py` (1 findings)

#### F183 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:66b873ee981a4d79#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_session_info.py::TestSessionInfo::test_session_has_token`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_set_attribute.py` (1 findings)

#### F184 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:030f8ed6c59d6e21#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_set_attribute.py::TestSetAttributeNegative::test_cannot_change_modulus`
- **Message:** Failed: write read-only CKA_MODULUS on an RSA public key: claimed success and the read-only value actually changed
- **Evidence:** tpm2: C_SetAttributeValue on read-only CKA_MODULUS of an RSA public key claimed success AND the modulus actually changed to the new value. CKA_MODULUS is read-only (PKCS#11 Base Table 12). policy attribute/permission self-contradiction with crypto-correctness impact (public-key identity is tied to the modulus).

### `test_sign.py` (1 findings)

#### F185 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:50192a4828a7a42b#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_sign.py::TestRSASignature::test_rsa_hash_mechanisms[SHA1]`
- **Message:** assert False is True
 +  where False = _verify_or_xfail(RawSession(raw=<pkcs11_check.raw.api.RawPKCS11 object at 0x7eb738c5fcb0>, sh=72057594037927937, slot_id=1), 1106, <CKM_SHA1_RSA_PKCS: 0x00000006>, b'hash mechanism test data', b'V\xb2\xabu\xc0q\xf2\xce\xe5%\xba\xe3\xcf\n \xd5u;\xf5\x8b3g9.\x87\
- **Evidence:** tpm2: CKM_SHA1_RSA_PKCS verify of a valid RSA hash-mechanism signature returns False (signature does not verify). Documented in module-issues.md 'ACVP RSA SHA-1 PKCS#1 SigVer rejects valid signatures'. Same SHA-1 SigVer reject-valid class — advertised verification behavior, not a loader issue.

### `test_stateful.py` (1 findings)

#### F186 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b3954e26881279d8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_stateful.py::test_pkcs11_stateful`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_stress.py` (1 findings)

#### F187 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8e19ecc7bc3b79bb#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_stress.py::TestMultiSessionConcurrency::test_sequential_multi_session`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for resource/stress setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for resource/stress setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_subprocess_safety.py` (1 findings)

#### F188 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:630c286b2b384299#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_subprocess_safety.py::TestForkSafety::test_fork_after_initialize`
- **Message:** subprocess.TimeoutExpired: Command '['/app/.venv/bin/python', '-c', '\nimport atexit as _p11check_atexit\nimport json as _p11check_json\nimport os as _p11check_os\nimport signal as _p11check_signal\n\n\ndef _p11check_rv_trace_enabled():\n    _value = _p11check_os.environ.get("PKCS11_CHECK_RV_TRACE",
- **Evidence:** tpm2: test_fork_after_initialize child re-initialize/finalize path times out after 15 seconds. Documented in module-issues.md 'Remaining-gap and subprocess-safety focused rerun'. TPM2 subprocess-safety/daemon behavior — the child cannot re-initialize the library after fork.

### `test_surface_audit.py` (1 findings)

#### F189 [LOW/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:94d6ade6f7bc2e37#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_surface_audit.py::TestMechanismFlagsConsistency::test_key_size_range_respected`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **Evidence:** tpm2: test_key_size_range_respected calls gen_aes_key directly (no xfail wrapper) and hard-fails on CKR_FUNCTION_NOT_SUPPORTED. This is the documented no-symmetric-keygen-surface deviation (module-issues PC-6). The test should use the shared advertised-keygen classifier like other AES-setup tests.

### `test_tool_templates.py` (2 findings)

#### F190 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a3c7ddb420a7dd9f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_tool_templates.py::TestDefaultToolTemplates::test_pkcs11_tool_aes_defaults`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but key generation is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F191 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:94e5672c46cdc75c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_tool_templates.py::TestDefaultToolTemplates::test_pkcs11_tool_rsa_defaults`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** Capability gap: RSA_PKCS_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_ATTRIBUTE_VALUE_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_v30_session.py` (1 findings)

#### F192 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:19bb6f4d97354aef#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_v30_session.py::TestLoginLogoutCycle::test_normal_login_logout`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_GEN advertised but AES-128 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Capability gap: AES_KEY_GEN advertised but AES-128 key generation for setup is not operational: CKR_FUNCTION_NOT_SUPPORTED. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_wycheproof.py` (2 findings)

#### F193 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7ee8c377d4aa2254`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 72
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5[tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CBC-PAD tc1: advertised AES-CBC-PAD decrypt is not operational: CKR_GENERAL_ERROR
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

#### F194 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:00bed1395486cd2a`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 988
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP256Wycheproof::test_ecdsa_p256_sha256_verify[tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: ECDSA:key-import: advertised but not operational (secp256r1: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_wycheproof_ecdh.py` (1 findings)

#### F195 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:45e088afc340e2c9`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 5495
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py::test_ecdh[ecdh_brainpoolP224r1_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: ECDH:EC-private-import: advertised but not operational (CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_wycheproof_ecdsa.py` (1 findings)

#### F196 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:401ca04a9931ea33`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 11907
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py::test_ecdsa_wycheproof[ecdsa_brainpoolP224r1_sha224_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: ECDSA:key-import: advertised but not operational (brainpoolp224r1: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_wycheproof_rsa_decrypt.py` (2 findings)

#### F197 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:064d6ae2357356e6`
- **Direction:** `CAPABILITY_GAP` · **Outcome:** `xfail` · **Tests covered:** 198
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_decrypt.py::test_rsa_pkcs1_decrypt[rsa_pkcs1_2048_test.json:tc2-valid]`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS:key-import: advertised but not operational (2048-bit private key import not operational (cached))
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F198 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:15584c43b8d695b0`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_decrypt.py::test_rsa_pkcs1_decrypt[rsa_pkcs1_2048_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS:key-import: advertised but not operational (2048-bit private key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_wycheproof_rsa_oaep.py` (2 findings)

#### F199 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:61d701c909810d3a`
- **Direction:** `CAPABILITY_GAP` · **Outcome:** `xfail` · **Tests covered:** 1076
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_oaep.py::test_rsa_oaep[rsa_oaep_2048_sha1_mgf1sha1_test.json:tc2-valid]`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_OAEP:key-import: advertised but not operational (2048-bit private key import not operational (cached))
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F200 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d29558244e345e00`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 9
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_oaep.py::test_rsa_oaep[rsa_oaep_2048_sha1_mgf1sha1_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_OAEP:key-import: advertised but not operational (2048-bit private key: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_wycheproof_rsa_pss.py` (9 findings)

#### F201 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:abc5e182f8dc46e4`
- **Direction:** `OTHER` · **Outcome:** `xfail` · **Tests covered:** 20
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py::test_rsa_pss[rsa_pss_4096_sha256_mgf1_32_test.json:tc67-invalid]`
- **Message:** _pytest.outcomes.XFailed: rsa_pss_4096_sha256_mgf1_32_test.json:tc67-invalid: accepted a genuine PSS signature whose salt length differs from the declared sLen=32 -- salt-length policy not enforced (not forgeable without the private key)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F202 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:e91e2d210b83ab85`
- **Direction:** `OTHER` · **Outcome:** `xfail` · **Tests covered:** 13
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py::test_rsa_pss[rsa_pss_2048_sha256_mgf1_32_params_test.json:tc67-invalid]`
- **Message:** _pytest.outcomes.XFailed: rsa_pss_2048_sha256_mgf1_32_params_test.json:tc67-invalid: accepted a genuine PSS signature whose salt length differs from the declared sLen=32 -- salt-length policy not enforced (not forgeable without the private key)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F203 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:7636101758df821d`
- **Direction:** `OTHER` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py::test_rsa_pss[rsa_pss_3072_sha256_mgf1_32_params_test.json:tc67-invalid]`
- **Message:** _pytest.outcomes.XFailed: rsa_pss_3072_sha256_mgf1_32_params_test.json:tc67-invalid: accepted a genuine PSS signature whose salt length differs from the declared sLen=32 -- salt-length policy not enforced (not forgeable without the private key)
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F204 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:453b9686bd9f047d`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 43
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py::test_rsa_pss[rsa_pss_2048_sha1_mgf1_20_params_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: Valid rsa_pss_2048_sha1_mgf1_20_params_test.json:tc1-valid rejected; PSS combo probe inconclusive (RSA-2048 keypair staging failed: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK) -- cannot distinguish deviation from module bug, recorded as xfail
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F205 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:889c3049d3897d22#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 256
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py::test_rsa_pss[rsa_pss_2048_sha256_mgf1_0_params_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: rsa_pss_2048_sha256_mgf1_0_params_test.json:tc1-valid: advertised RSA-PSS parameters are not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: rsa_pss_2048_sha256_mgf1_0_params_test.json:tc1-valid: advertised RSA-PSS parameters are not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F206 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e1aed0dd10c1f2bf#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 132
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py::test_rsa_pss[rsa_pss_4096_sha512_mgf1_32_params_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: rsa_pss_4096_sha512_mgf1_32_params_test.json:tc1-valid: advertised RSA-PSS parameters are not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: rsa_pss_4096_sha512_mgf1_32_params_test.json:tc1-valid: advertised RSA-PSS parameters are not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F207 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fbee7f3edc153fe0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 116
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py::test_rsa_pss[rsa_pss_misc_params_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: rsa_pss_misc_params_test.json:tc1-valid: advertised RSA-PSS parameters are not operational: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: rsa_pss_misc_params_test.json:tc1-valid: advertised RSA-PSS parameters are not operational: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F208 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d4ae20b9c8b6301e#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 51
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py::test_rsa_pss[rsa_pss_4096_sha256_mgf1_32_test.json:tc107-invalid]`
- **Message:** _pytest.outcomes.XFailed: rsa_pss_4096_sha256_mgf1_32_test.json:tc107-invalid: signature verification rejected with non-clean CKR: CKR_ARGUMENTS_BAD
- **Evidence:** RSA padding hash-variant gap: rsa_pss_4096_sha256_mgf1_32_test.json:tc107-invalid: signature verification rejected with non-clean CKR: CKR_ARGUMENTS_BAD. Module only supports subset of RFC 8017 hash/MGF combinations.

#### F209 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4383cf5283eeeb80#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py::test_rsa_pss[rsa_pss_3072_sha256_mgf1_32_params_test.json:tc107-invalid]`
- **Message:** _pytest.outcomes.XFailed: rsa_pss_3072_sha256_mgf1_32_params_test.json:tc107-invalid: signature verification rejected with non-clean CKR: CKR_ARGUMENTS_BAD
- **Evidence:** RSA padding hash-variant gap: rsa_pss_3072_sha256_mgf1_32_params_test.json:tc107-invalid: signature verification rejected with non-clean CKR: CKR_ARGUMENTS_BAD. Module only supports subset of RFC 8017 hash/MGF combinations.

### `test_wycheproof_rsa_siggen.py` (3 findings)

#### F210 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2fa7bd747a7293c5`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 24
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_siggen.py::test_rsa_pkcs1_siggen[rsa_pkcs1_2048_sig_gen_test.json:tc81]`
- **Message:** _pytest.outcomes.XFailed: SHA256_RSA_PKCS:key-import: advertised but not operational (2048-bit SHA-256: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F211 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3412bf3f415754ab`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 24
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_siggen.py::test_rsa_pkcs1_siggen[rsa_pkcs1_2048_sig_gen_test.json:tc89]`
- **Message:** _pytest.outcomes.XFailed: SHA384_RSA_PKCS:key-import: advertised but not operational (2048-bit SHA-384: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F212 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:15fac6c73819dde3`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 24
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_siggen.py::test_rsa_pkcs1_siggen[rsa_pkcs1_2048_sig_gen_test.json:tc97]`
- **Message:** _pytest.outcomes.XFailed: SHA512_RSA_PKCS:key-import: advertised but not operational (2048-bit SHA-512: CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_wycheproof_x25519.py` (1 findings)

#### F213 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:052919e7965d2f84`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1017
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_x25519.py::test_xdh[x25519_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: ECDH:Montgomery-private-import: advertised but not operational (CKR_ATTRIBUTE_VALUE_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_lifecycle.py` (1 findings)

#### F214 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:90e393a758c7116e#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/x509/test_lifecycle.py::TestCertificateLifecycle::test_cert_modifiability`
- **Message:** Failed: Successfully modified label on non-modifiable cert
- **Evidence:** tpm2: C_SetAttributeValue(CKA_LABEL) succeeded on a certificate created with CKA_MODIFIABLE=False, and the label actually changed. policy self-contradiction: claimed non-modifiable then honored a modification.


## Already documented in `docs/module-issues.md` (45 findings)

These records match an existing module-issues.md entry. Not re-listed here to avoid duplication; see `verdicts.jsonl` for individual pointers.

## Not yet classified (72 groups, DEFERRED)

Per user directive m0213-m0214, classification extension stopped. These will be classified by an in-tool workflow.

Top by size:
| Group size | Direction | Test file | Signature |
|---:|---|---|---|
| 148 | CLEAN_ERROR | `test_acvp_hmac.py` | `sha1:5741e7a39978a1fa` |
| 148 | CLEAN_ERROR | `test_acvp_hmac.py` | `sha1:17e84873eaa1c963` |
| 148 | CLEAN_ERROR | `test_acvp_hmac.py` | `sha1:fbc84c1847791fea` |
| 139 | REJECT_VALID | `test_wycheproof_rsa_pss.py` | `sha1:db7d59a104ec8796` |
| 66 | CLEAN_ERROR | `test_wycheproof.py` | `sha1:dabc66746d77f8ff` |
| 66 | CLEAN_ERROR | `test_wycheproof_hmac.py` | `sha1:584e539db4c205b7` |
| 66 | CLEAN_ERROR | `test_wycheproof_hmac.py` | `sha1:c0411d10bcdbac67` |
| 66 | CLEAN_ERROR | `test_wycheproof_hmac.py` | `sha1:5deb319b887af70b` |
| 24 | REJECT_VALID | `test_wycheproof_rsa.py` | `sha1:dec7deb70fb24d9c` |
| 5 | CLEAN_ERROR | `test_recover_length_boundary.py` | `sha1:206524d47269c5f6` |
| 5 | CLEAN_ERROR | `test_access_levels.py` | `sha1:e74bcb09b4e0f858` |
| 4 | CLEAN_ERROR | `test_kat.py` | `sha1:8ebb6c1c0e554d79` |
| 4 | CLEAN_ERROR | `test_kat.py` | `sha1:46aae1e8bc2deff6` |
| 4 | CLEAN_ERROR | `test_mech_attribute.py` | `sha1:16827a723ce5cd9a` |
| 4 | CLEAN_ERROR | `test_mech_attribute.py` | `sha1:4e72f5b07b9b9db4` |
