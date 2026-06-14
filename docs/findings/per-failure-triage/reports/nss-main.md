# nss-main — Per-Failure Triage

**Effective records:** 488
**Categories:** {'PROVIDER_BUG': 260, 'KNOWN_ISSUE': 117, 'UNKNOWN': 57, 'SOFT_TOKEN_CAVEAT': 54}
**Severities:** {'LOW': 253, 'INFO': 88, 'MEDIUM': 85, 'HIGH': 62}

## Findings (314)

Ordered by severity then category.

### `-` (3 findings)

#### F001 [HIGH/PROVIDER_BUG] —  PROVIDER_REPORT(nss-main)
- **Signature:** `crash:nss-main:src/pkcs11_check/testcases/test_mech_flags.py`
- **Direction:** `CRASH` · **Outcome:** `crashed` · **Tests covered:** 3
- **Example nodeid:** ``
- **Message:** SIGSEGV (rc=11) during mechanism-flags behavioral probe. Shard-0 per-test traces show 3 crashes in TestMechFlagBehavioralConformance::test_sign_flag_callable[AES/CAMELLIA/CDMF_MAC_GENERAL] -- mechanis
- **Evidence:** SIGSEGV (rc=11) during mechanism-flags behavioral probe. Shard-0 per-test traces show 3 crashes in TestMechFlagBehavioralConformance::test_sign_flag_callable[AES/CAMELLIA/CDMF_MAC_GENERAL] -- mechanisms that ADVERTISE CKF_SIGN. Python stack: _probe_init_with_key (line 175) -> raw _call. NSS softoken dereferences an invalid pointer during a sign-init on an advertised mechanism rather than performing the op. Real provider bug.

#### F002 [HIGH/PROVIDER_BUG] —  PROVIDER_REPORT(nss-main)
- **Signature:** `crash:nss-main:src/pkcs11_check/testcases/test_mech_negative.py`
- **Direction:** `CRASH` · **Outcome:** `crashed` · **Tests covered:** 3
- **Example nodeid:** ``
- **Message:** SIGSEGV (rc=11) during negative-mechanism ops. Shard-0 per-test traces show 3 crashes: test_hmac_sha256_with_rsa_key_rejected (wrong key type, spec wants CKR_KEY_TYPE_INVALID) and test_registry_sign_m
- **Evidence:** SIGSEGV (rc=11) during negative-mechanism ops. Shard-0 per-test traces show 3 crashes: test_hmac_sha256_with_rsa_key_rejected (wrong key type, spec wants CKR_KEY_TYPE_INVALID) and test_registry_sign_missing_required_param[AES/CAMELLIA_MAC_GENERAL] (missing param, spec wants CKR_TEMPLATE_INCOMPLETE). NSS softoken segfaults on out-of-contract mechanism input instead of validating and returning a CKR error.

#### F003 [HIGH/PROVIDER_BUG] —  PROVIDER_REPORT(nss-main)
- **Signature:** `crash:nss-main:src/pkcs11_check/testcases/test_operation_termination.py`
- **Direction:** `CRASH` · **Outcome:** `crashed` · **Tests covered:** 3
- **Example nodeid:** ``
- **Message:** SIGSEGV (rc=11) during operation-termination / NULL-argument probe. Shard-0 per-test traces show 3 crashes in test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-length/encrypt-u
- **Evidence:** SIGSEGV (rc=11) during operation-termination / NULL-argument probe. Shard-0 per-test traces show 3 crashes in test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-length/encrypt-update-length/decrypt-length]. Python stack: _call_null_arg_enc_dec -> raw _call. Spec requires CKR_ARGUMENTS_BAD for NULL arguments; NSS softoken segfaults instead of validating the pointer. Real provider bug.

### `test_acvp_eddsa.py` (4 findings)

#### F004 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:c271e7de8d6aa4ea`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::TestEdDsaKeyVer::test_eddsa_keyver[EDDSA-KeyVer-ED-25519-tc1]`
- **Message:** Failed: EDDSA-KeyVer-ED-25519-tc1: Module ACCEPTED an INVALID EdDSA key
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F005 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:300e892f621d0479`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::TestEdDsaKeyVer::test_eddsa_keyver[EDDSA-KeyVer-ED-25519-tc4]`
- **Message:** Failed: EDDSA-KeyVer-ED-25519-tc4: Module ACCEPTED an INVALID EdDSA key
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F006 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6dc9193f8452dc28#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 5
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::test_acvp_eddsa_siggen[EDDSA-SigGen-ED-25519-tc41]`
- **Message:** _pytest.outcomes.XFailed: EDDSA-SigGen-ED-25519-tc41: advertised EdDSA operation rejected: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: EDDSA-SigGen-ED-25519-tc41: advertised EdDSA operation rejected: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F007 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0f6c0ffbcad95edf#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_eddsa.py::TestEdDsaKeyGen::test_eddsa_keygen[EDDSA-KeyGen-ED-25519-tc1]`
- **Message:** _pytest.outcomes.XFailed: EDDSA-KeyGen-ED-25519-tc1: advertised EdDSA operation rejected: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: EDDSA-KeyGen-ED-25519-tc1: advertised EdDSA operation rejected: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_ckr_decrypt.py` (1 findings)

#### F008 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:dd7f96a964381bee#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_decrypt.py::TestDecryptDataErrors::test_key_function_not_permitted`
- **Message:** _pytest.outcomes.XFailed: C_DecryptInit(key_CKA_DECRYPT_is_False): rejected with CKR_KEY_TYPE_INCONSISTENT, spec prefers ['CKR_KEY_FUNCTION_NOT_PERMITTED'] [PKCS#11 v3.1 Sec.5.9.1]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_DecryptInit(key_CKA_DECRYPT_is_False): rejected with CKR_KEY_TYPE_INCONSISTENT, spec prefers ['CKR_KEY_FUNCTION_NOT_PERMITTED'] [PKCS#11 v3.1 Sec.5.9.1]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_derive.py` (1 findings)

#### F009 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:16f3bc1aea949828#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_derive.py::TestDeriveKeyErrors::test_key_type_inconsistent`
- **Message:** _pytest.outcomes.XFailed: C_DeriveKey(base_key_type_wrong_for_mechanism): rejected with CKR_KEY_HANDLE_INVALID, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.14.5]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_DeriveKey(base_key_type_wrong_for_mechanism): rejected with CKR_KEY_HANDLE_INVALID, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.1 Sec.5.14.5]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_encrypt.py` (1 findings)

#### F010 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8ac639cbcc624f10#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_encrypt.py::TestEncryptInitErrors::test_key_function_not_permitted`
- **Message:** _pytest.outcomes.XFailed: C_EncryptInit(key_CKA_ENCRYPT_is_False): rejected with CKR_KEY_TYPE_INCONSISTENT, spec prefers ['CKR_KEY_FUNCTION_NOT_PERMITTED'] [PKCS#11 v3.1 Sec.5.8.1]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_EncryptInit(key_CKA_ENCRYPT_is_False): rejected with CKR_KEY_TYPE_INCONSISTENT, spec prefers ['CKR_KEY_FUNCTION_NOT_PERMITTED'] [PKCS#11 v3.1 Sec.5.8.1]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_kem.py` (1 findings)

#### F011 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6f272d9bacfe0055#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_kem.py::TestEncapsulateKeyErrors::test_key_type_inconsistent`
- **Message:** _pytest.outcomes.XFailed: C_EncapsulateKey(RSA_key_with_ML_KEM_mechanism): rejected with CKR_KEY_HANDLE_INVALID, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.2 Sec.5.14.7]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_EncapsulateKey(RSA_key_with_ML_KEM_mechanism): rejected with CKR_KEY_HANDLE_INVALID, spec prefers ['CKR_KEY_TYPE_INCONSISTENT'] [PKCS#11 v3.2 Sec.5.14.7]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_keygen.py` (7 findings)

#### F012 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:7b72f230318492ea`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyPairErrors::test_public_token_bool_overlong_length`
- **Message:** Failed: C_GenerateKeyPair with CK_ULONG-sized private CKA_TOKEN boolean attribute: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F013 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:b4585ebb45e5eacb`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyPairErrors::test_ec_token_bool_overlong_length[public-template]`
- **Message:** Failed: EC C_GenerateKeyPair with CK_ULONG-sized private CKA_TOKEN boolean attribute: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F014 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:968fc8f86613ddd7`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyPairErrors::test_ml_kem_parameter_set_ulong_malformed_length[public-underlong]`
- **Message:** Failed: ML-KEM C_GenerateKeyPair with underlong private CKA_PARAMETER_SET CK_ULONG attribute: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F015 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:0be43b6e7a26d2c7`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyPairErrors::test_ml_kem_parameter_set_ulong_malformed_length[public-overlong]`
- **Message:** Failed: ML-KEM C_GenerateKeyPair with overlong private CKA_PARAMETER_SET CK_ULONG attribute: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F016 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:aa8881f10b490794`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyErrors::test_token_bool_overlong_length`
- **Message:** Failed: C_GenerateKey with CK_ULONG-sized CKA_TOKEN boolean attribute: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F017 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:5405de0fa8efa445`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyErrors::test_value_len_ulong_malformed_length[underlong]`
- **Message:** Failed: C_GenerateKey with underlong CKA_VALUE_LEN CK_ULONG attribute: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F018 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:1180238a30b000ea`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyErrors::test_value_len_ulong_malformed_length[overlong]`
- **Message:** Failed: C_GenerateKey with overlong CKA_VALUE_LEN CK_ULONG attribute: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

### `test_ckr_object.py` (6 findings)

#### F019 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:cc80d4002c7816e4`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_object.py::TestCreateObjectErrors::test_class_ulong_malformed_length[underlong]`
- **Message:** Failed: C_CreateObject with underlong CKA_CLASS CK_ULONG attribute: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F020 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:256ae2f55dcde5e1`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_object.py::TestCreateObjectErrors::test_class_ulong_malformed_length[overlong]`
- **Message:** Failed: C_CreateObject with overlong CKA_CLASS CK_ULONG attribute: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F021 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:058259338deff154`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_object.py::TestCreateObjectErrors::test_token_bool_overlong_length`
- **Message:** Failed: C_CreateObject with CK_ULONG-sized CKA_TOKEN boolean attribute: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F022 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:4da749ced8f58052`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_object.py::TestCreateObjectErrors::test_allowed_mechanisms_null_pointer_nonzero_length`
- **Message:** Failed: C_CreateObject with CKA_ALLOWED_MECHANISMS NULL_PTR and nonzero ulValueLen: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F023 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:74277237401fc3f4`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_object.py::TestCopyObjectErrors::test_copy_token_bool_overlong_length`
- **Message:** Failed: C_CopyObject with CK_ULONG-sized CKA_TOKEN boolean attribute: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F024 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:327c8759d236227c#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_object.py::TestCreateObjectErrors::test_allowed_mechanisms_empty_null_pointer_enforced`
- **Message:** Failed: CKA_ALLOWED_MECHANISMS empty-array enforcement for C_EncryptInit/C_Encrypt: claimed the protection then violated it (self-contradiction)
- **Evidence:** A key created with an empty CKA_ALLOWED_MECHANISMS array (NULL_PTR, ulValueLen=0) reads back as [] yet still permits C_EncryptInit/C_Encrypt with CKM_AES_ECB (CKR_OK) instead of CKR_MECHANISM_INVALID / CKR_KEY_FUNCTION_NOT_PERMITTED. policy self-contradiction (claimed the restriction then violated it). Documented NSS finding (module-issues.md:264-272); shared with opencryptoki; softhsm2/kryoptic/wolfpkcs11 enforce.

### `test_ckr_raw_buffer.py` (6 findings)

#### F025 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:096be681354cac5e`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestDecryptBufferTooSmallGuards::test_aes_cbc_pad_decrypt_buffer_too_small_preserves_guard_and_retries`
- **Message:** Failed: C_Decrypt AES-CBC-PAD undersized output buffer guard: subprocess failed with exit code 1
stdout: CKR:0x00000150
LEN:1
OVERWRITTEN:0
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

#### F026 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9f97b3353fe18f25`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestDecryptBufferTooSmallGuards::test_aes_cbc_pad_decrypt_final_buffer_too_small_preserves_guard_and_retries`
- **Message:** Failed: C_DecryptFinal AES-CBC-PAD undersized output buffer guard: subprocess failed with exit code 1
stdout: CKR:0x00000150
LEN:0
OVERWRITTEN:0
RETRY_CKR:0x00000091
RETRY_LEN:31
RETRY_MATCH:0
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlot
- **Evidence:** Vaudenay padding oracle: AES-CBC-PAD accepts invalid padding. Real provider bug.

#### F027 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:bff27217ca8b8e04#phase6`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestListBufferTooSmallGuards::test_get_mechanism_list_buffer_too_small_preserves_guard`
- **Message:** Failed: C_GetMechanismList undersized list buffer guard: module crashed with signal 11
stdout: 
stderr:
- **Evidence:** C_GetMechanismList with undersized list buffer crashes signal 11 instead of returning CKR_BUFFER_TOO_SMALL (PKCS#11 two-call convention). Related to documented NSS output-buffer-overrun family (module-issues.md names C_GetMechanismList) but the segfault is the distinct finding: a segfault IS the finding.

#### F028 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cd5a99c2a394070e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestListBufferTooSmallGuards::test_get_slot_list_buffer_too_small_preserves_guard`
- **Message:** Failed: C_GetSlotList undersized list buffer guard: subprocess failed with exit code 1
stdout: CKR:0x00000000
LEN:2
OVERWRITTEN:8
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"C_Get
- **Evidence:** C_GetSlotList with a 1-entry declared buffer returned CKR_OK and OVERWrote 8 guard bytes (declared LEN=2 found slots, OVERWRITTEN=8). Real out-of-bounds write past caller's buffer instead of CKR_BUFFER_TOO_SMALL. Documented NSS output-buffer-overrun family (module-issues.md:214-223). Cross-provider: softhsm2/kryoptic/opencryptoki return CKR_BUFFER_TOO_SMALL cleanly.

#### F029 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a7cbe066796d3d4e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestAttributeBufferTooSmallGuards::test_get_attribute_value_buffer_too_small_preserves_guard_and_retries`
- **Message:** Failed: C_GetAttributeValue undersized attribute buffer guard: subprocess failed with exit code 1
stdout: NEEDED:30
CKR:0x00000000
LEN:30
OVERWRITTEN:29
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_
- **Evidence:** C_GetAttributeValue with a 1-byte declared buffer returned CKR_OK and OVERWrote 29 guard bytes (NEEDED:30, LEN:30, OVERWRITTEN:29). Real out-of-bounds write instead of CKR_BUFFER_TOO_SMALL. Same documented NSS overrun family (module-issues.md:218 lists C_GetAttributeValue).

#### F030 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:405d4f06b480a987#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestByteOutputBufferTooSmallGuards::test_wrap_key_buffer_too_small_preserves_guard`
- **Message:** AssertionError: C_WrapKey reported required length 1, expected 32
assert 1 == 32
- **Evidence:** C_WrapKey on an undersized output buffer reported a required length of 1 byte when the true wrapped-key length is 32 bytes (assert 1 == 32). Caller can never size the buffer from the size query. PKCS#11 5.2 requires the true required length. Same documented NSS output-buffer family (module-issues.md:218 lists C_WrapKey).

### `test_ckr_wrap.py` (2 findings)

#### F031 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ddc422bc02fd1fa6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_wrap.py::TestWrapKeyErrors::test_key_not_extractable`
- **Message:** Failed: C_WrapKey on a CKA_EXTRACTABLE=False key (PKCS#11 v3.1 Sec.5.14.3 requires CKR_KEY_UNEXTRACTABLE): claimed the protection then violated it (self-contradiction)
- **Evidence:** C_WrapKey succeeded (CKR_OK) on a key whose CKA_EXTRACTABLE=False reads back as False, instead of CKR_KEY_UNEXTRACTABLE (PKCS#11 v3.1 Sec.5.14.3). policy self-contradiction: claimed the non-extractable protection then violated it (key material leaves the token). Documented NSS finding (module-issues.md:519-527); softhsm2 enforces and passes.

#### F032 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:96659c0242d30e3c`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_wrap.py::TestUnwrapKeyErrors::test_unwrap_token_bool_overlong_length`
- **Message:** Failed: C_UnwrapKey with CK_ULONG-sized CKA_TOKEN boolean attribute: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

### `test_arithmetic_overflow.py` (1 findings)

#### F033 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:d59cf2eccde28b40`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestTemplateCountOverflow::test_template_count_overflow[find_objects_init-ulong_max]`
- **Message:** Failed: C_FindObjectsInit(template_count=0x100000000): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_ffi_length_boundary.py` (19 findings)

#### F034 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:3e6c980924d3601d`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestPbeNestedLengthBoundary::test_pbe_nested_length_boundary[pbe_sha1_des3-password-isize_max]`
- **Message:** Failed: C_GenerateKey(CKM_PBE_SHA1_DES3_EDE_CBC, password length=0x7fffffffffffffff): accepted invalid (CKR_OK) -- must reject
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F035 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:a7a670625c34206f`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestPbeNestedLengthBoundary::test_pbe_nested_length_boundary[pbe_sha1_des2-password-isize_max]`
- **Message:** Failed: C_GenerateKey(CKM_PBE_SHA1_DES2_EDE_CBC, password length=0x7fffffffffffffff): accepted invalid (CKR_OK) -- must reject
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F036 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:7c16b0be903b664c`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestPbeNestedLengthBoundary::test_pbe_nested_length_boundary[pba_sha1_hmac-password-isize_max]`
- **Message:** Failed: C_GenerateKey(CKM_PBA_SHA1_WITH_SHA1_HMAC, password length=0x7fffffffffffffff): accepted invalid (CKR_OK) -- must reject
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F037 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:30d0f91d132f6a61`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_sign_isize_boundary[isize_max]`
- **Message:** Failed: C_Sign(HMAC_SHA256, ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F038 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:ad0c4a6ae0f50ba4`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_verify_isize_data_len[isize_max]`
- **Message:** Failed: C_Verify(HMAC_SHA256, ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F039 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:1e8bb7a8cf6c6737`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestPbkdf2NestedLengthBoundary::test_pbkdf2_nested_length_boundary[password-isize_max]`
- **Message:** Failed: C_GenerateKey(PBKDF2, password length=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F040 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:328c8a9374e5ca5d`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestPbkdf2NestedLengthBoundary::test_pbkdf2_nested_length_boundary[prf_data-isize_max]`
- **Message:** Failed: C_GenerateKey(PBKDF2, prf_data length=0x7fffffffffffffff): accepted invalid (CKR_OK) -- must reject
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F041 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:e90678ac80b6b91b`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestSp800108NestedCountBoundary::test_sp800_108_additional_derived_key_count_boundary[isize_max]`
- **Message:** Failed: C_DeriveKey(SP800_108_COUNTER_KDF, additional-derived-key count=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F042 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:51f4aedb93c3251f`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestMessageApiLengthBoundary::test_decrypt_message_isize_input_len[associated_data_len-isize_max]`
- **Message:** Failed: C_DecryptMessage(associated_data=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F043 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:9a3ca807efe6ae1a`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[sign_update-isize_max]`
- **Message:** Failed: C_SignUpdate(ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_SignUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F044 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:bc2de4727a1e103c`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[sign_update-isize_max_plus_1]`
- **Message:** Failed: C_SignUpdate(ulDataLen=0x8000000000000000): module crashed with signal 11
stdout: TARGET:C_SignUpdate
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F045 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:b04b41fa3db70ee5`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[verify_update-isize_max]`
- **Message:** Failed: C_VerifyUpdate(ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_VerifyUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F046 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:612b51bb8b5e4456`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[verify_update-isize_max_plus_1]`
- **Message:** Failed: C_VerifyUpdate(ulDataLen=0x8000000000000000): module crashed with signal 11
stdout: TARGET:C_VerifyUpdate
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F047 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:3a67521632dff188`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRandomIsizeLength::test_seed_random_isize_length_rejects_cleanly[isize_max]`
- **Message:** Failed: C_SeedRandom(ulSeedLen=0x7fffffffffffffff): subprocess failed with exit code 1
stdout: TARGET:C_SeedRandom
LEN:9223372036854775807
rv=CKR_OK
rv_name=CKR_OK
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F048 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:ef4b5a2c53920c56`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRandomIsizeLength::test_seed_random_isize_length_rejects_cleanly[isize_max_plus_1]`
- **Message:** Failed: C_SeedRandom(ulSeedLen=0x8000000000000000): subprocess failed with exit code 1
stdout: TARGET:C_SeedRandom
LEN:9223372036854775808
rv=CKR_OK
rv_name=CKR_OK
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F049 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:ffd258ca63923185`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestMechanismNullInnerParams::test_gcm_null_iv`
- **Message:** Failed: C_EncryptInit(AES_GCM, pIv=NULL, ulIvLen=12): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F050 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:18d527104b49c051`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestRsaPssSaltLengthBoundary::test_rsa_pss_salt_length_boundary[isize_max_plus_1]`
- **Message:** Failed: C_Sign(SHA256_RSA_PKCS_PSS, sLen=0x8000000000000000): accepted invalid (CKR_OK) -- must reject
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F051 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:f9c112325eb2c137`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestPbkdf2NestedLengthBoundary::test_pbkdf2_nested_length_boundary[salt-isize_max_plus_1]`
- **Message:** Failed: C_GenerateKey(PBKDF2, salt length=0x8000000000000000): accepted invalid (CKR_OK) -- must reject
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F052 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:43b317826707b4fa`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestPbkdf2NestedLengthBoundary::test_pbkdf2_nested_length_boundary[salt-isize_max]`
- **Message:** _pytest.outcomes.XFailed: C_GenerateKey(CKM_PBE_SHA1_DES2_EDE_CBC, salt length=0x7fffffffffffffff): rejected with CKR_MECHANISM_INVALID, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_DATA_LEN_RANGE', 'CKR_KEY_SIZE_RANGE', 'CKR_TEMPLATE_INCOMPLETE',
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_ffi_null_pointer.py` (7 findings)

#### F053 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:aeb975f7959bac7d#phase6`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestNullDataUpdate::test_null_data_update[C_SignUpdate]`
- **Message:** Failed: C_SignUpdate(data=NULL, data_len=32): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** C_SignUpdate(data=NULL, data_len=32) crashes signal 11. PKCS#11 section 2.3.3 requires CKR_ARGUMENTS_BAD when a required pointer is NULL with nonzero length. Reclassified from earlier Denis-KEEP UB disposition: NULL-arg validation is a spec-required conformance case.

#### F054 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:09accbd00fa92e1c#phase6`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestNullDataUpdate::test_null_data_update[C_VerifyUpdate]`
- **Message:** Failed: C_VerifyUpdate(data=NULL, data_len=32): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** C_VerifyUpdate(data=NULL, data_len=32) crashes signal 11. PKCS#11 section 2.3.3 requires CKR_ARGUMENTS_BAD for NULL pointer with nonzero length. Reclassified from earlier Denis-KEEP UB disposition.

#### F055 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fb91deb9ca82d1bd#phase6`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestNullRandomBuffer::test_seed_random_null_buffer`
- **Message:** Failed: C_SeedRandom(data=NULL, data_len=32): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** C_SeedRandom(data=NULL, data_len=32) crashes signal 11. PKCS#11 section 2.3.3 requires CKR_ARGUMENTS_BAD for NULL pointer with nonzero length. Reclassified from earlier Denis-KEEP UB disposition.

#### F056 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:98e9667a95ba6d49#phase6`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestNullRandomBuffer::test_generate_random_null_buffer`
- **Message:** Failed: C_GenerateRandom(buf=NULL, buf_len=32): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** C_GenerateRandom(buf=NULL, buf_len=32) crashes signal 11. PKCS#11 section 2.3.3 requires CKR_ARGUMENTS_BAD for NULL pointer with nonzero length. Reclassified from earlier Denis-KEEP UB disposition.

#### F057 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:864ecb6dceced501#phase6`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestNullOperationState::test_set_operation_state_null_buffer`
- **Message:** Failed: C_SetOperationState(state=NULL, state_len=32): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** C_SetOperationState(state=NULL, state_len=32) crashes signal 11. PKCS#11 section 2.3.3 requires CKR_ARGUMENTS_BAD for NULL pointer with nonzero length. Reclassified from earlier Denis-KEEP UB disposition.

#### F058 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5da3e8b4d83cb77d#phase6`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestNullDataOneShot::test_null_data_oneshot[C_Sign]`
- **Message:** Failed: C_Sign(data=NULL, data_len=32): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** C_Sign(data=NULL, data_len=32) crashes signal 11. PKCS#11 section 2.3.3 requires CKR_ARGUMENTS_BAD for NULL pointer with nonzero length. Reclassified from earlier Denis-KEEP UB disposition.

#### F059 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b45534b2213d450a#phase6`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestNullDataOneShot::test_null_data_oneshot[C_Verify]`
- **Message:** Failed: C_Verify(data=NULL, data_len=32): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** C_Verify(data=NULL, data_len=32) crashes signal 11. PKCS#11 section 2.3.3 requires CKR_ARGUMENTS_BAD for NULL pointer with nonzero length. Reclassified from earlier Denis-KEEP UB disposition.

### `test_parameter_validation.py` (6 findings)

#### F060 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:7dd8f4c3da837f26`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmTagSize::test_gcm_weak_tag_size[tag-32-bits]`
- **Message:** Failed: AES-GCM with 32-bit tag (below NIST 96-bit minimum): accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F061 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:e571b547b769cb9d`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmTagSize::test_gcm_weak_tag_size[tag-64-bits]`
- **Message:** Failed: AES-GCM with 64-bit tag (below NIST 96-bit minimum): accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F062 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:f2531a90b6b238e5`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmIvWeakness::test_gcm_weak_iv[single-zero-byte-iv]`
- **Message:** Failed: AES-GCM with 1-byte IV (below NIST 96-bit recommendation): accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F063 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:e481e8eab2aff203`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmIvWeakness::test_gcm_weak_iv[4-zero-bytes-iv]`
- **Message:** Failed: AES-GCM with 4-byte IV (below NIST 96-bit recommendation): accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F064 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c124f25c0f5499c9`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmTagSize::test_gcm_weak_tag_size[tag-0-bits]`
- **Message:** _pytest.outcomes.XFailed: AES-GCM with 0-bit tag (below NIST 96-bit minimum): rejected with CKR_HOST_MEMORY, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F065 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:875bcd6e19dc19a1`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_parameter_validation.py::TestGcmTagSize::test_gcm_weak_tag_size[tag-8-bits]`
- **Message:** _pytest.outcomes.XFailed: AES-GCM with 8-bit tag (below NIST 96-bit minimum): rejected with CKR_HOST_MEMORY, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_KEY_SIZE_RANGE', 'CKR_DATA_LEN_RANGE', 'CKR_ARGUMENTS_BAD', 'CKR_TEMPLATE_INCONSISTENT']
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

### `test_recover_length_boundary.py` (4 findings)

#### F066 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3f8ab4557443c287#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_recover_length_boundary.py::TestRecoverOutputLengthBoundary::test_verify_recover_one_byte_output_preserves_guard`
- **Message:** Failed: C_VerifyRecover one-byte output buffer guard: subprocess failed with exit code 1
stdout: P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_
- **Evidence:** C_VerifyRecover with a 1-byte declared output buffer made the guard subprocess exit 1 (buffer-guard probe failed): NSS does not return CKR_BUFFER_TOO_SMALL + required length, instead overrunning/aborting the size protocol. New variant of the documented NSS output-buffer-overrun family (module-issues.md:214-223) extended to the VerifyRecover output path; same memory-safety class.

#### F067 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:c79cf3af31f3369d`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_recover_length_boundary.py::TestRecoverInputLengthBoundary::test_sign_recover_huge_data_len_does_not_crash[isize_max_plus_1]`
- **Message:** Failed: C_SignRecover with ulDataLen=0x8000000000000000: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F068 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:a4d76c7f7030392e`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_recover_length_boundary.py::TestRecoverInputLengthBoundary::test_verify_recover_huge_signature_len_does_not_crash[isize_max]`
- **Message:** _pytest.outcomes.XFailed: C_VerifyRecover with ulSignatureLen=0x7fffffffffffffff: rejected with CKR_SIGNATURE_INVALID, expected ['CKR_SIGNATURE_LEN_RANGE']
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F069 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:cd3b17c6d0ec1347`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_recover_length_boundary.py::TestRecoverInputLengthBoundary::test_sign_recover_huge_data_len_does_not_crash[isize_max]`
- **Message:** _pytest.outcomes.XFailed: C_SignRecover with ulDataLen=0x7fffffffffffffff: rejected with CKR_DEVICE_ERROR, expected ['CKR_DATA_LEN_RANGE']
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_access_control.py` (1 findings)

#### F070 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f76808000d66cf06#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_access_control.py::TestCopyObject::test_non_copyable_key_rejected`
- **Message:** Failed: SECURITY: module copied a CKA_COPYABLE=False key — copy-prohibition silently ignored
- **Evidence:** C_CopyObject succeeded (CKR_OK) on a key created with CKA_COPYABLE=False; the copy-prohibition attribute is silently ignored. PKCS#11 v3.1 Sec.4.9.1 requires CKR_ACTION_PROHIBITED. Documented NSS behavior (module-issues.md:615-617 'CKA_COPYABLE not enforced'); this access-control test surfaces the documented quirk as a security finding (copy-protection bypass).

### `test_aes_modes.py` (2 findings)

#### F071 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:526ee50eaae6931c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_aes_modes.py::TestAESCTR::test_aes_ctr_counter_bits_zero_rejected`
- **Message:** _pytest.outcomes.XFailed: C_EncryptInit with ulCounterBits=0 (spec range 1-128): rejected with CKR_HOST_MEMORY, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_EncryptInit with ulCounterBits=0 (spec range 1-128): rejected with CKR_HOST_MEMORY, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F072 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7e2965c4d38d86cf#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_aes_modes.py::TestAESXCBCMAC::test_aes_xcbc_mac_sign_verify`
- **Message:** _pytest.outcomes.XFailed: Module returns CKR_KEY_TYPE_INCONSISTENT for CKM_AES_XCBC_MAC C_VerifyInit; the advertised XCBC-MAC verify path rejects CKK_AES keys even when CKA_VERIFY=True (sign works but verify is broken)
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: Module returns CKR_KEY_TYPE_INCONSISTENT for CKM_AES_XCBC_MAC C_VerifyInit; the advertised XCBC-MAC verify path rejects CKK_AES keys even when CKA_VERIFY=True (sign works but verify is broken). Direction = reject-valid → functional gap (LOW).

### `test_authenticated_wrap.py` (1 findings)

#### F073 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:070919c920a9d3b5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_authenticated_wrap.py::TestAuthenticatedWrap::test_aes_gcm_wrap_unwrap`
- **Message:** _pytest.outcomes.XFailed: AES-GCM authenticated generated-IV wrap rejected: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-GCM authenticated generated-IV wrap rejected: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK. Direction = reject-valid → functional gap (LOW).

### `test_cctv_ed25519.py` (1 findings)

#### F074 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:de59fa533dc7f7c0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 914
- **Example nodeid:** `src/pkcs11_check/testcases/test_cctv_ed25519.py::test_ed25519_cctv[vec0-low_order_R,low_order_A,low_or]`
- **Message:** _pytest.outcomes.XFailed: CCTV Ed25519 vector 0: signature verification rejected with non-clean CKR: CKR_FUNCTION_NOT_SUPPORTED
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CCTV Ed25519 vector 0: signature verification rejected with non-clean CKR: CKR_FUNCTION_NOT_SUPPORTED. Direction = reject-valid → functional gap (LOW).

### `test_dh_key_agreement.py` (2 findings)

#### F075 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e680c2e3faeadfe9#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_dh_key_agreement.py::TestDHKeyAgreement::test_dh_pkcs_derive_rfc3526_group14_rejects_zero_value_len`
- **Message:** AssertionError: accepted CKM_DH_PKCS_DERIVE RFC 3526 Group 14 CKA_VALUE_LEN=0
- **Evidence:** CKM_DH_PKCS_DERIVE (RFC 3526 Group 14) accepted CKA_VALUE_LEN=0 and returned CKR_OK instead of CKR_TEMPLATE_INCONSISTENT / CKR_ATTRIBUTE_VALUE_INVALID. Accept-invalid on a derivation template attribute (a zero-length derived key is nonsensical). Not yet documented for NSS; new finding.

#### F076 [LOW/PROVIDER_BUG] — 📚 DOCS_ONLY
- **Signature:** `sha1:5ab1b7bbf4e66426#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_dh_key_agreement.py::TestDHKeyAgreement::test_dh_derive_rejects_missing_peer_public_value`
- **Message:** _pytest.outcomes.XFailed: CKM_DH_PKCS_DERIVE malformed peer public value: rejected with CKR_HOST_MEMORY, expected ['CKR_ARGUMENTS_BAD', 'CKR_DOMAIN_PARAMS_INVALID', 'CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** CKM_DH_PKCS_DERIVE with a malformed peer public value rejected with CKR_HOST_MEMORY instead of CKR_ARGUMENTS_BAD / CKR_DOMAIN_PARAMS_INVALID / CKR_MECHANISM_PARAM_INVALID. CKR_HOST_MEMORY (out-of-memory) is a misleading wrong CKR for a malformed-input reject. Clean error, no crash; already xfailed by the test. Minor CKR-mislabel on an error path.

### `test_hkdf_extended.py` (3 findings)

#### F077 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b2801b91b246c806#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_hkdf_extended.py::TestHKDFData::test_hkdf_data_derive`
- **Message:** _pytest.outcomes.XFailed: HKDF_DATA derive failed: CKR_TEMPLATE_INCONSISTENT
- **Evidence:** Capability gap: NSS CKM_HKDF_DATA derive rejected with CKR_TEMPLATE_INCONSISTENT. Advertised mechanism not operational in derive mode.

#### F078 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b16df4e3284ff0ec#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_hkdf_extended.py::TestHKDFKeyGen::test_hkdf_key_gen_basic[CKK_HKDF]`
- **Message:** _pytest.outcomes.XFailed: CKM_HKDF_KEY_GEN advertised but key_type=0x10 keygen rejected: CKR_MECHANISM_INVALID
- **Evidence:** Capability gap: NSS CKM_HKDF_KEY_GEN rejects CKK_HKDF (0x10) key type with CKR_MECHANISM_INVALID. HKDF keygen not operational for tested key types.

#### F079 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1c9d992f49717a29#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_hkdf_extended.py::TestHKDFKeyGen::test_hkdf_key_gen_usable_for_derive`
- **Message:** _pytest.outcomes.XFailed: CKM_HKDF_KEY_GEN advertised but no tested key type is operational: CKM_HKDF_KEY_GEN C_GenerateKey: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK; CKM_HKDF_KEY_GEN C_GenerateKey: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** Capability gap: NSS CKM_HKDF_KEY_GEN not operational for any tested key type (CKR_MECHANISM_INVALID). The ACCEPT_INVALID direction label is misleading — module cleanly rejects all key types.

### `test_ike.py` (1 findings)

#### F080 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:49b2b79fe1ac2d8e#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_ike.py::TestIKEPRFDerive::test_derive_aes128`
- **Message:** AssertionError: assert 32 == 16
 +  where 32 = len(b'\x90\x9b\xe3\x92y\xfe\xc3\xad\x8b\x16Tj\x95it\xeeC[\xb4\xac\xfa\x8f\x0c\x91g\xf0\xf0\x19\xff\x97\x7fE')
 +    where b'\x90\x9b\xe3\x92y\xfe\xc3\xad\x8b\x16Tj\x95it\xeeC[\xb4\xac\xfa\x8f\x0c\x91g\xf0\xf0\x19\xff\x97\x7fE' = _get_value(RawSession(ra
- **Evidence:** CKM_IKE_PRF_DERIVE with CKA_VALUE_LEN=16 returned CKR_OK but produced a 32-byte derived key (assert len(derived)==32, expected 16). crypto wrong-output: the derived key length does not match the requested CKA_VALUE_LEN (PKCS#11 derive semantics require the requested length). Distinct from the documented IKE CKR_MECHANISM_PARAM_INVALID stub (module-issues.md:805-822) -- here IKE_PRF_DERIVE IS operational but emits the wrong-length output. Crypto-correctness break on key derivation.

### `test_kdf.py` (1 findings)

#### F081 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:72bc4c4c5f0c2844#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_kdf.py::TestHKDF::test_hkdf_derive_basic`
- **Message:** _pytest.outcomes.XFailed: HKDF derivation not operational: CKR_TEMPLATE_INCONSISTENT
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: HKDF derivation not operational: CKR_TEMPLATE_INCONSISTENT. Direction = reject-valid → functional gap (LOW).

### `test_key_usage_policy.py` (2 findings)

#### F082 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fac6a108e450e676#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_key_usage_policy.py::TestAESKeyUsagePolicy::test_decrypt_only_key_cannot_encrypt`
- **Message:** _pytest.outcomes.XFailed: C_EncryptInit on a SIGN-only AES key created CKA_ENCRYPT=False: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_KEY_FUNCTION_NOT_PERMITTED']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_EncryptInit on a SIGN-only AES key created CKA_ENCRYPT=False: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_KEY_FUNCTION_NOT_PERMITTED']. Direction = reject-valid → functional gap (LOW).

#### F083 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5904ced231f8a634#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_key_usage_policy.py::TestAESKeyUsagePolicy::test_encrypt_only_key_cannot_decrypt`
- **Message:** _pytest.outcomes.XFailed: C_DecryptInit on an AES key created CKA_DECRYPT=False: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_KEY_FUNCTION_NOT_PERMITTED']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_DecryptInit on an AES key created CKA_DECRYPT=False: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_KEY_FUNCTION_NOT_PERMITTED']. Direction = reject-valid → functional gap (LOW).

### `test_mech_attribute.py` (4 findings)

#### F084 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f25973de11763b08#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_attribute.py::TestKeyAttributes::test_key_type_matches_template[HKDF_KEY_GEN]`
- **Message:** _pytest.outcomes.XFailed: HKDF_KEY_GEN keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: HKDF_KEY_GEN keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F085 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:39f09c91575858ad#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_attribute.py::TestKeyAttributes::test_local_flag_on_generated_key[PBA_SHA1_WITH_SHA1_HMAC]`
- **Message:** _pytest.outcomes.XFailed: PBA_SHA1_WITH_SHA1_HMAC keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: PBA_SHA1_WITH_SHA1_HMAC keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F086 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:28364803acc52752#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_attribute.py::TestKeyAttributes::test_local_flag_on_generated_key[PBE_SHA1_DES2_EDE_CBC]`
- **Message:** _pytest.outcomes.XFailed: PBE_SHA1_DES2_EDE_CBC keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: PBE_SHA1_DES2_EDE_CBC keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F087 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8eeb692776bd07e0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_attribute.py::TestKeyAttributes::test_local_flag_on_generated_key[PBE_SHA1_DES3_EDE_CBC]`
- **Message:** _pytest.outcomes.XFailed: PBE_SHA1_DES3_EDE_CBC keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: PBE_SHA1_DES3_EDE_CBC keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_mech_derive.py` (1 findings)

#### F088 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a9d8bdf8fddfa75e`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_derive.py::TestMechDerive::test_derive_produces_key[HKDF_DERIVE]`
- **Message:** _pytest.outcomes.XFailed: HKDF_DERIVE:derive: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_encrypt.py` (1 findings)

#### F089 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a50f5bc1227cd954`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_encrypt.py::TestMechEncryptRoundtrip::test_roundtrip[RC2_ECB]`
- **Message:** _pytest.outcomes.XFailed: RC2_ECB:encrypt: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_keygen.py` (4 findings)

#### F090 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:160bf22eafa84bf7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_keygen.py::TestMechKeygen::test_generate_key[HKDF_KEY_GEN]`
- **Message:** _pytest.outcomes.XFailed: HKDF_KEY_GEN keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: HKDF_KEY_GEN keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F091 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d30e57e70172840a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_keygen.py::TestMechKeygen::test_generate_key[PBA_SHA1_WITH_SHA1_HMAC]`
- **Message:** _pytest.outcomes.XFailed: PBA_SHA1_WITH_SHA1_HMAC keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: PBA_SHA1_WITH_SHA1_HMAC keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F092 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:581212dd53092a04#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_keygen.py::TestMechKeygen::test_generate_key[PBE_SHA1_DES2_EDE_CBC]`
- **Message:** _pytest.outcomes.XFailed: PBE_SHA1_DES2_EDE_CBC keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: PBE_SHA1_DES2_EDE_CBC keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F093 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:29601567836b09c9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_keygen.py::TestMechKeygen::test_generate_key[PBE_SHA1_DES3_EDE_CBC]`
- **Message:** _pytest.outcomes.XFailed: PBE_SHA1_DES3_EDE_CBC keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: PBE_SHA1_DES3_EDE_CBC keygen rejected at runtime: CKR_MECHANISM_PARAM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_mech_lifecycle.py` (1 findings)

#### F094 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:526a5e5ca9669f09#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_lifecycle.py::TestHKDFDerivedKeyUse::test_hkdf_to_aes_encrypt`
- **Message:** _pytest.outcomes.XFailed: HKDF base key generation rejected on advertised lifecycle path: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: HKDF base key generation rejected on advertised lifecycle path: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_mech_message.py` (6 findings)

#### F095 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:d23644b844f36f31`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_encrypt_wrong_key_type[AES_GCM]`
- **Message:** Failed: AES_GCM C_MessageEncryptInit with malformed non-NULL params: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F096 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:6254563e753a9e18`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_encrypt_wrong_key_type[CHACHA20_POLY1305]`
- **Message:** Failed: CHACHA20_POLY1305 C_MessageEncryptInit with malformed non-NULL params: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F097 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:bfe210730f6bd134`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_decrypt_wrong_key_type[AES_GCM]`
- **Message:** Failed: AES_GCM C_MessageDecryptInit with malformed non-NULL params: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F098 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:91ba88ac992a3bb9`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_message.py::TestRegistryMessageWrongKeyType::test_registry_message_decrypt_wrong_key_type[CHACHA20_POLY1305]`
- **Message:** Failed: CHACHA20_POLY1305 C_MessageDecryptInit with malformed non-NULL params: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F099 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ba381c9db92a751f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_message.py::TestRegistryMessagePermission::test_registry_message_encrypt_without_flag[AES_GCM]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_GCM keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F100 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2ec5a2170ac194ce#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_message.py::TestRegistryMessagePermission::test_registry_message_encrypt_without_flag[CHACHA20_POLY1305]`
- **Message:** _pytest.outcomes.XFailed: CHACHA20_POLY1305 keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CHACHA20_POLY1305 keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_mech_multipart.py` (32 findings)

#### F101 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:db7b75d3e9967f1d`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD:multipart-decrypt: advertised but not operational (CKR_ENCRYPTED_DATA_LEN_RANGE)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F102 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:976f388365bfc907`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB:multipart-encrypt: advertised but not operational (CKR_OPERATION_NOT_INITIALIZED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F103 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d08a385c0afb5b49`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[CAMELLIA_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: CAMELLIA_CBC_PAD:multipart-decrypt: advertised but not operational (CKR_ENCRYPTED_DATA_LEN_RANGE)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F104 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5762fedbeab087d8`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[CAMELLIA_ECB]`
- **Message:** _pytest.outcomes.XFailed: CAMELLIA_ECB:multipart-encrypt: advertised but not operational (CKR_OPERATION_NOT_INITIALIZED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F105 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c27ca8851fd5acbd`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[CDMF_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: CDMF_CBC_PAD:multipart-decrypt: advertised but not operational (CKR_ENCRYPTED_DATA_LEN_RANGE)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F106 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4c64ab7b4edeaa6d`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[CDMF_ECB]`
- **Message:** _pytest.outcomes.XFailed: CDMF_ECB:multipart-encrypt: advertised but not operational (CKR_OPERATION_NOT_INITIALIZED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F107 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b833fecc9ddda0b1`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[CHACHA20]`
- **Message:** _pytest.outcomes.XFailed: CHACHA20:multipart-decrypt: advertised but not operational (CKR_OPERATION_NOT_INITIALIZED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F108 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f4505106f3e0c813`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[DES3_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC:multipart-encrypt: advertised but not operational (CKR_OPERATION_ACTIVE)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F109 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3489227ce851d67d`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[DES3_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC_PAD:multipart-decrypt: advertised but not operational (CKR_ENCRYPTED_DATA_LEN_RANGE)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F110 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a4d8d2e0d5c373a4`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[DES3_ECB]`
- **Message:** _pytest.outcomes.XFailed: DES3_ECB:multipart-encrypt: advertised but not operational (CKR_OPERATION_NOT_INITIALIZED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F111 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:61ff7ec1eda69401`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[DES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC_PAD:multipart-decrypt: advertised but not operational (CKR_ENCRYPTED_DATA_LEN_RANGE)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F112 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e88055cb15509aa0`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[DES_ECB]`
- **Message:** _pytest.outcomes.XFailed: DES_ECB:multipart-encrypt: advertised but not operational (CKR_OPERATION_NOT_INITIALIZED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F113 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0cf99f828b7c44c3`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[RC2_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: RC2_CBC_PAD:multipart-decrypt: advertised but not operational (CKR_ENCRYPTED_DATA_LEN_RANGE)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F114 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:da4de771459b4b05`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[RC2_ECB]`
- **Message:** _pytest.outcomes.XFailed: RC2_ECB:multipart-encrypt: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F115 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:67660063dfa2c1a5`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[SEED_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: SEED_CBC_PAD:multipart-decrypt: advertised but not operational (CKR_ENCRYPTED_DATA_LEN_RANGE)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F116 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6fd5f06da2aa2ddd`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartEncrypt::test_streaming_equals_single[SEED_ECB]`
- **Message:** _pytest.outcomes.XFailed: SEED_ECB:multipart-encrypt: advertised but not operational (CKR_OPERATION_NOT_INITIALIZED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F117 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b6bf8f9d671fdce1`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[AES_CMAC]`
- **Message:** _pytest.outcomes.XFailed: AES_CMAC:multipart-verify: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F118 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:43500dc3874d957f`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[AES_CMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: AES_CMAC_GENERAL:multipart-sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F119 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:95d1bc95bf7cfb20`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[AES_XCBC_MAC]`
- **Message:** _pytest.outcomes.XFailed: AES_XCBC_MAC:multipart-verify: advertised but not operational (CKR_KEY_TYPE_INCONSISTENT)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F120 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:54991f0210a31bcd`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[AES_XCBC_MAC_96]`
- **Message:** _pytest.outcomes.XFailed: AES_XCBC_MAC_96:multipart-verify: advertised but not operational (CKR_KEY_TYPE_INCONSISTENT)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F121 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8e03bc09c2494c7c`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[EDDSA]`
- **Message:** _pytest.outcomes.XFailed: EDDSA:multipart-sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F122 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8aacacd131ae9627`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[MD2_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: MD2_HMAC_GENERAL:multipart-sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F123 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6b780008484ad9bf`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[MD5_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: MD5_HMAC_GENERAL:multipart-sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F124 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cbb462e2587cadb6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[SHA224_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA224_HMAC_GENERAL:multipart-sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F125 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0ca93c307b92e7cd`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[SHA256_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC_GENERAL:multipart-sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F126 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a1d56d6c33cfbff3`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[SHA384_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA384_HMAC_GENERAL:multipart-sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F127 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:01fd4ef8f4196141`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[SHA3_224_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_224_HMAC_GENERAL:multipart-sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F128 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9fbaa176a0704e87`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[SHA3_256_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_256_HMAC_GENERAL:multipart-sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F129 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:aeea53ff21a5b6e9`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[SHA3_384_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_384_HMAC_GENERAL:multipart-sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F130 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:72fc7d78c00c67d3`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[SHA3_512_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_512_HMAC_GENERAL:multipart-sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F131 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d32aec3fee038c0d`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[SHA512_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA512_HMAC_GENERAL:multipart-sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F132 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fe5c934aad45363a`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_multipart.py::TestMultipartSign::test_multipart_sign_verify[SHA_1_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA_1_HMAC_GENERAL:multipart-sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_mech_negative.py` (91 findings)

#### F133 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:660e8d1862ccca2e`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[AES_CMAC]`
- **Message:** Failed: AES_CMAC sign with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F134 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:025993bb23e4c34e`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[AES_XCBC_MAC]`
- **Message:** Failed: AES_XCBC_MAC sign with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F135 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:d3c182d96a703fee`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[AES_XCBC_MAC_96]`
- **Message:** Failed: AES_XCBC_MAC_96 sign with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F136 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:72f428c8f71c02c6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[MD2_HMAC]`
- **Message:** Failed: MD2_HMAC sign with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F137 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:c9c16a748585a856`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[MD5_HMAC]`
- **Message:** Failed: MD5_HMAC sign with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F138 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:5cfb24801bbd7e3a`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[MD2_HMAC]`
- **Message:** Failed: MD2_HMAC verify with wrong key type: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F139 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:42cc56e2bdbe68a1`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_malformed_required_param[AES_CBC_PAD]`
- **Message:** Failed: AES_CBC_PAD C_EncryptInit with malformed non-NULL params: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F140 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:44e15e3b05436baa`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_GCM]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Reject-valid on AEAD: false negative (clean CKR error). Per severity-direction principle, LOW severity — functional bug, not oracle.

#### F141 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7dfe75c3b23d5af3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 5
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[CAMELLIA_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: CAMELLIA_CBC_PAD C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CAMELLIA_CBC_PAD C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F142 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f0a77aaf9f57d947#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[CDMF_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: CDMF_CBC_PAD C_DecryptInit with missing required params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CDMF_CBC_PAD C_DecryptInit with missing required params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F143 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c4def32573637b96#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[DES3_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC_PAD C_DecryptInit with missing required params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC_PAD C_DecryptInit with missing required params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F144 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:08797d6891ecf1e2#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[DES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC_PAD C_DecryptInit with missing required params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC_PAD C_DecryptInit with missing required params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F145 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:65407a4f4fade140#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[AES_CMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: AES_CMAC_GENERAL C_SignInit with missing required params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CMAC_GENERAL C_SignInit with missing required params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID']. Direction = reject-valid → functional gap (LOW).

#### F146 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:72dd6c839869d2a9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC_PAD C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F147 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f44c4315f9867282#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_malformed_required_param[CAMELLIA_CBC]`
- **Message:** _pytest.outcomes.XFailed: CAMELLIA_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CAMELLIA_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F148 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2a9a4522b149d44c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_malformed_required_param[CHACHA20_POLY1305]`
- **Message:** _pytest.outcomes.XFailed: CHACHA20_POLY1305 C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CHACHA20_POLY1305 C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F149 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:235e3ffed4cc5252#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_malformed_required_param[RC2_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: RC2_CBC_PAD C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RC2_CBC_PAD C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F150 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7e1f8111f7010cee#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_malformed_required_param[RSA_PKCS_OAEP]`
- **Message:** _pytest.outcomes.XFailed: RSA_PKCS_OAEP C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RSA_PKCS_OAEP C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F151 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6b736bbbca264bd9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_malformed_required_param[SEED_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: SEED_CBC_PAD C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SEED_CBC_PAD C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F152 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:406216dc9232c47b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[MD2_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: MD2_HMAC_GENERAL sign with wrong key type: rejected with CKR_MECHANISM_PARAM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: MD2_HMAC_GENERAL sign with wrong key type: rejected with CKR_MECHANISM_PARAM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F153 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:10e28fd2f9eb5bf3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[MD5_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: MD5_HMAC_GENERAL sign with wrong key type: rejected with CKR_MECHANISM_PARAM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: MD5_HMAC_GENERAL sign with wrong key type: rejected with CKR_MECHANISM_PARAM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F154 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:438b70420855aee8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_KEY_WRAP_KWP]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_WRAP_KWP keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_WRAP_KWP keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F155 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:69a894b6f13fdc48#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_KEY_WRAP_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_WRAP_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_WRAP_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F156 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:85a022625f44077a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[CDMF_CBC]`
- **Message:** _pytest.outcomes.XFailed: CDMF_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CDMF_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F157 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5e28c183376813fd#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[DES3_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F158 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c1366791cec3d9b2#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_missing_required_param[DES_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F159 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b4624d36a8337766#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F160 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d0f5f66240462620#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F161 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ba2ab2600bb85364#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[AES_CTS]`
- **Message:** _pytest.outcomes.XFailed: AES_CTS C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTS C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F162 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4021424b2b882ef8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[CDMF_CBC]`
- **Message:** _pytest.outcomes.XFailed: CDMF_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CDMF_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F163 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fbe22de56937417b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[CHACHA20]`
- **Message:** _pytest.outcomes.XFailed: CHACHA20 C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CHACHA20 C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F164 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:25d57610a2fe4790#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[DES3_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F165 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6e673ca21f2df325#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[DES_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F166 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7206b08ef58633a0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[RC2_CBC]`
- **Message:** _pytest.outcomes.XFailed: RC2_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RC2_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F167 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:65b75f216114c06e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[RC2_ECB]`
- **Message:** _pytest.outcomes.XFailed: RC2_ECB C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RC2_ECB C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F168 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2e0337bc71698e3d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_decrypt_missing_required_param[SEED_CBC]`
- **Message:** _pytest.outcomes.XFailed: SEED_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SEED_CBC C_DecryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F169 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:148126d177150128#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[AES_CMAC]`
- **Message:** _pytest.outcomes.XFailed: AES_CMAC verify with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CMAC verify with wrong key type: rejected with CKR_MECHANISM_INVALID, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F170 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:743c99618b2ed63f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[MD5_HMAC]`
- **Message:** _pytest.outcomes.XFailed: MD5_HMAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: MD5_HMAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F171 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:901f47e8615226c7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[RC2_MAC]`
- **Message:** _pytest.outcomes.XFailed: RC2_MAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RC2_MAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F172 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fd36d8192a0832b3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[RC2_MAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: RC2_MAC_GENERAL verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RC2_MAC_GENERAL verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F173 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:53cffbb4aa0646a8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[SEED_MAC]`
- **Message:** _pytest.outcomes.XFailed: SEED_MAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SEED_MAC verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F174 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:27106b61ca8d0af2#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_verify_wrong_key_type[SEED_MAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SEED_MAC_GENERAL verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SEED_MAC_GENERAL verify with wrong key type: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F175 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:93ec847b9f74dca0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F176 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:19d0b12d68384350#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F177 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:adfccf539a8e193b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F178 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9e257f02c655fecf#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[AES_KEY_WRAP]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_WRAP wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_WRAP wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F179 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8d2cd68413dbc3ad#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[CAMELLIA_CBC]`
- **Message:** _pytest.outcomes.XFailed: CAMELLIA_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CAMELLIA_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F180 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:825b013d626419b7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[CAMELLIA_ECB]`
- **Message:** _pytest.outcomes.XFailed: CAMELLIA_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CAMELLIA_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F181 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:45f58d59cadaa376#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[CDMF_CBC]`
- **Message:** _pytest.outcomes.XFailed: CDMF_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CDMF_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F182 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2ccb2ae819c1e383#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[CDMF_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: CDMF_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CDMF_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F183 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d3b8ac03964f1d4b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[CDMF_ECB]`
- **Message:** _pytest.outcomes.XFailed: CDMF_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CDMF_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F184 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:09e139c1d3cf000b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES3_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F185 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5eaf8b7feb09d659#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES3_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F186 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a6b78d386cc80082#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES3_ECB]`
- **Message:** _pytest.outcomes.XFailed: DES3_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F187 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2b7abf6500338565#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F188 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b120a5d8ffaaa678#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F189 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:79e274d68e496bdd#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[DES_ECB]`
- **Message:** _pytest.outcomes.XFailed: DES_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F190 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:84467ba6be724d88#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[RC2_CBC]`
- **Message:** _pytest.outcomes.XFailed: RC2_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RC2_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F191 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:771a7cdb9abddcc1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[RC2_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: RC2_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RC2_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F192 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:32dcd5b7506e78cc#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[RC2_ECB]`
- **Message:** _pytest.outcomes.XFailed: RC2_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RC2_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F193 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7d478ce30f8bde8b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[SEED_CBC]`
- **Message:** _pytest.outcomes.XFailed: SEED_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SEED_CBC wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F194 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b7ac1915d0c64398#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[SEED_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: SEED_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SEED_CBC_PAD wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F195 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8598a6eaf2c7dae5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_wrap_wrong_key_type[SEED_ECB]`
- **Message:** _pytest.outcomes.XFailed: SEED_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SEED_ECB wrap with wrong key type: rejected with CKR_KEY_TYPE_INCONSISTENT, expected ['CKR_WRAPPING_KEY_TYPE_INCONSISTENT']. Direction = reject-valid → functional gap (LOW).

#### F196 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:399295913306a29c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_CBC]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F197 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:350784d0ddd9b6ae#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: AES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F198 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a6f601d7e12c5444#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_ECB]`
- **Message:** _pytest.outcomes.XFailed: AES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F199 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:90cb15f99022cbad#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[AES_KEY_WRAP]`
- **Message:** _pytest.outcomes.XFailed: AES_KEY_WRAP keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_KEY_WRAP keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F200 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:512c09912dfbf5b2#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[CAMELLIA_CBC]`
- **Message:** _pytest.outcomes.XFailed: CAMELLIA_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CAMELLIA_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F201 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:508b5d0f04eb123e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[CAMELLIA_ECB]`
- **Message:** _pytest.outcomes.XFailed: CAMELLIA_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CAMELLIA_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F202 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:007d1f106404c1b6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[CDMF_CBC]`
- **Message:** _pytest.outcomes.XFailed: CDMF_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CDMF_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F203 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4e32d53ab75542c0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[CDMF_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: CDMF_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CDMF_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F204 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8487da0b25492acd#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[CDMF_ECB]`
- **Message:** _pytest.outcomes.XFailed: CDMF_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CDMF_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F205 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2f76862d6e3115e8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES3_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F206 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e3ea9e65a0a0b7ed#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES3_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES3_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F207 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:69d1ceeec0f0e8fe#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES3_ECB]`
- **Message:** _pytest.outcomes.XFailed: DES3_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES3_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F208 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8eb823681c3ede0f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES_CBC]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F209 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fa133a3290e8ebb1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: DES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F210 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4d313158d56fe10d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[DES_ECB]`
- **Message:** _pytest.outcomes.XFailed: DES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: DES_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F211 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:91d535f156556091#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[RC2_CBC]`
- **Message:** _pytest.outcomes.XFailed: RC2_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RC2_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F212 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:65d8a0583dcb74bb#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[RC2_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: RC2_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RC2_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F213 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1c54c8820cb316f3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[RC2_ECB]`
- **Message:** _pytest.outcomes.XFailed: RC2_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RC2_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F214 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:08e1237faf5a2bf7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[SEED_CBC]`
- **Message:** _pytest.outcomes.XFailed: SEED_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SEED_CBC keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F215 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0d213f58f75d6381#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[SEED_CBC_PAD]`
- **Message:** _pytest.outcomes.XFailed: SEED_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SEED_CBC_PAD keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F216 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e027e7d0ac42bbfc#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_unwrap_wrong_key_type[SEED_ECB]`
- **Message:** _pytest.outcomes.XFailed: SEED_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SEED_ECB keygen rejected at runtime: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F217 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d7d2c4a218ece612#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_malformed_required_param[AES_CTR]`
- **Message:** _pytest.outcomes.XFailed: AES_CTR C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTR C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F218 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e2533c5d2134e41d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_malformed_required_param[AES_CTS]`
- **Message:** _pytest.outcomes.XFailed: AES_CTS C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CTS C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F219 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e084dcc37488a90a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_malformed_required_param[AES_GCM]`
- **Message:** _pytest.outcomes.XFailed: AES_GCM C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_GCM C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F220 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:11c713f6d54a9d18#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_malformed_required_param[CHACHA20]`
- **Message:** _pytest.outcomes.XFailed: CHACHA20 C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: CHACHA20 C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F221 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:91beccff0e5b5839#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_malformed_required_param[RC2_CBC]`
- **Message:** _pytest.outcomes.XFailed: RC2_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RC2_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F222 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a5b4010bbc0fc93a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_malformed_required_param[RC2_ECB]`
- **Message:** _pytest.outcomes.XFailed: RC2_ECB C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RC2_ECB C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

#### F223 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e5bff03f16bb45a0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestBadParameters::test_registry_encrypt_malformed_required_param[SEED_CBC]`
- **Message:** _pytest.outcomes.XFailed: SEED_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: SEED_CBC C_EncryptInit with malformed non-NULL params: rejected with CKR_OPERATION_ACTIVE, expected ['CKR_MECHANISM_PARAM_INVALID', 'CKR_ARGUMENTS_BAD']. Direction = reject-valid → functional gap (LOW).

### `test_mech_sign.py` (19 findings)

#### F224 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3be07773cc82948f`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[AES_CMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: AES_CMAC_GENERAL:sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F225 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:80fa099015ff8781`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[AES_XCBC_MAC_96]`
- **Message:** _pytest.outcomes.XFailed: AES_XCBC_MAC_96: signature verification rejected with non-clean CKR: CKR_KEY_TYPE_INCONSISTENT
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F226 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:af74b4381a9fa3a2`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[EDDSA]`
- **Message:** _pytest.outcomes.XFailed: EDDSA:sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F227 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8cce4778e9f006d0`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[MD2_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: MD2_HMAC_GENERAL:sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F228 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9252e61d0e74ad0a`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[MD5_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: MD5_HMAC_GENERAL:sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F229 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:dea5234102728329`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[SHA224_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA224_HMAC_GENERAL:sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F230 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8213f715e68a8c5f`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[SHA256_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC_GENERAL:sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F231 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:64505cf587b58625`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[SHA384_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA384_HMAC_GENERAL:sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F232 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ac8b3314639d4769`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[SHA3_224_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_224_HMAC_GENERAL:sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F233 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4ff038769d1b1b4e`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[SHA3_256_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_256_HMAC_GENERAL:sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F234 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:dc621717321859fb`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[SHA3_384_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_384_HMAC_GENERAL:sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F235 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a21d614290f0f460`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[SHA3_512_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA3_512_HMAC_GENERAL:sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F236 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7597bf84764ee3d9`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[SHA512_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA512_HMAC_GENERAL:sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F237 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:735f75a263599fe5`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[SHA_1_HMAC_GENERAL]`
- **Message:** _pytest.outcomes.XFailed: SHA_1_HMAC_GENERAL:sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F238 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9235c4824807de2a`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[AES_CMAC]`
- **Message:** _pytest.outcomes.XFailed: AES_CMAC:verify: advertised but not operational (CKR_MECHANISM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F239 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:745d4b341ffb8d29`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[AES_XCBC_MAC]`
- **Message:** _pytest.outcomes.XFailed: AES_XCBC_MAC:verify: advertised but not operational (CKR_KEY_TYPE_INCONSISTENT)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F240 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3f7ad67d9a08d63e`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[EDDSA]`
- **Message:** _pytest.outcomes.XFailed: EDDSA:kat-sign: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F241 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:09deffd85d87e218#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_tampered_data_fails_verify[AES_CMAC]`
- **Message:** _pytest.outcomes.XFailed: AES_CMAC: signature verification rejected with non-clean CKR: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_CMAC: signature verification rejected with non-clean CKR: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F242 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cc33ba01042be7ce#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_tampered_data_fails_verify[AES_XCBC_MAC]`
- **Message:** _pytest.outcomes.XFailed: AES_XCBC_MAC: signature verification rejected with non-clean CKR: CKR_KEY_TYPE_INCONSISTENT
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES_XCBC_MAC: signature verification rejected with non-clean CKR: CKR_KEY_TYPE_INCONSISTENT. Direction = reject-valid → functional gap (LOW).

### `test_mech_wrap.py` (1 findings)

#### F243 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:52368807634689b2`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_wrap.py::TestMechWrapRoundtrip::test_wrap_unwrap_aes_key[RC2_ECB]`
- **Message:** _pytest.outcomes.XFailed: RC2_ECB:wrap: advertised but not operational (CKR_MECHANISM_PARAM_INVALID)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_message_crypto.py` (2 findings)

#### F244 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:85523ea7716edab3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_single`
- **Message:** _pytest.outcomes.XFailed: advertised message encrypt rejected (CKM_AES_CBC): CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: advertised message encrypt rejected (CKM_AES_CBC): CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F245 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6052a48341904d94#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_message_crypto.py::TestMessageEncryptDecrypt::test_message_encrypt_multipart`
- **Message:** _pytest.outcomes.XFailed: C_MessageEncryptInit rejected advertised message operation: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_MessageEncryptInit rejected advertised message operation: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_operation_termination.py` (1 findings)

#### F246 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b1347c881bb04788#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_null_argument_rejection_terminates_encrypt_decrypt_operation[encrypt-update-input]`
- **Message:** Failed: C_EncryptUpdate with NULL input pointer returned CKR_ARGUMENTS_BAD but left the encrypt operation active (next init -> CKR_OPERATION_ACTIVE): success claimed then contradicted (self-contradiction)
- **Evidence:** C_EncryptUpdate(NULL input, nonzero len) returned CKR_ARGUMENTS_BAD but left the encrypt op active; next C_EncryptInit -> CKR_OPERATION_ACTIVE. lifecycle self-contradiction (clean error then op not terminated). Cohort with documented NSS C_EncryptFinal non-termination family (module-issues.md:358-376); this is the NULL-input variant on the update path.

### `test_remaining_gaps.py` (2 findings)

#### F247 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f223c1ff3426a28c#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_remaining_gaps.py::TestTemplateConstraintAttributes::test_wrap_template_enforces_target_attributes`
- **Message:** Failed: CKA_WRAP_TEMPLATE target-attribute enforcement: claimed the protection then violated it (self-contradiction)
- **Evidence:** CKA_WRAP_TEMPLATE target-attribute constraint: a wrapping key with a CKA_WRAP_TEMPLATE is still allowed to wrap a target key whose attributes violate the template (CKR_OK) instead of CKR_KEY_FUNCTION_NOT_PERMITTED. policy self-contradiction (claimed the wrap policy then violated it). Same class as the documented NSS CKA_WRAP_WITH_TRUSTED / non-extractable wrap policy findings (module-issues.md:509-536). Not previously recorded for CKA_WRAP_TEMPLATE.

#### F248 [HIGH/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:aa13aa83aaa5d25f#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_remaining_gaps.py::TestTemplateConstraintAttributes::test_unwrap_template_enforces_created_object_attributes`
- **Message:** Failed: CKA_UNWRAP_TEMPLATE created-object enforcement: claimed the protection then violated it (self-contradiction)
- **Evidence:** CKA_UNWRAP_TEMPLATE created-object constraint: a wrapping key with a CKA_UNWRAP_TEMPLATE permits unwrapping a key whose resulting attributes violate the template (CKR_OK) instead of CKR_KEY_FUNCTION_NOT_PERMITTED / CKR_TEMPLATE_INCONSISTENT. policy self-contradiction (claimed the unwrap policy then violated it). Companion to the CKA_WRAP_TEMPLATE finding; same class as documented NSS wrap-policy findings.

### `test_set_attribute.py` (1 findings)

#### F249 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:6b22c4a40116babb#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_set_attribute.py::TestSetAttributeAtomicity::test_set_attribute_mixed_template_is_atomic`
- **Message:** Failed: C_SetAttributeValue partially applied CKA_LABEL before rejecting a later read-only CKA_CLASS row
- **Evidence:** C_SetAttributeValue with a mixed template (CKA_LABEL + read-only CKA_CLASS) partially applied CKA_LABEL then rejected the CKA_CLASS row, leaving the object in a half-modified state. Violates the PKCS#11 atomicity guarantee for C_SetAttributeValue (all-or-nothing). lifecycle/state self-contradiction (claimed success on one row, rejected another, object left inconsistent). Shared deviation (bouncyhsm/kryoptic also fail); not previously recorded for NSS.

### `test_sign_recover.py` (1 findings)

#### F250 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:3557ff60e0b3940b`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_sign_recover.py::TestSignRecoverRecipes::test_verify_recover_invalid_signature`
- **Message:** _pytest.outcomes.XFailed: Module C_VerifyRecover accepted invalid all-zero signature: valid=True, recovered=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

### `test_wycheproof_aes.py` (63 findings)

#### F251 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:11a182acc179ff26#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc1-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc1-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F252 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cdffe1d38ec1ded6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc2-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc2-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc2-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F253 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e21884b1b3e1cc3e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc3-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc3-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc3-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F254 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cdae21fd9a7d2a65#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc4-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc4-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc4-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F255 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:054810018fe7bde0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc5-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc5-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc5-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F256 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8302d87a9b98270d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc6-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc6-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc6-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F257 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:bb700eb2bcad60a3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc7-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc7-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc7-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F258 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5aad43f7655a1c52#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc8-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc8-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc8-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F259 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9bb72767a121e64a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc9-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc9-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc9-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F260 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7dcd880da3c4ddcc#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc10-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc10-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc10-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F261 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8859e640ab2c20a1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc11-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc11-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc11-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F262 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2bb1a19210d88f16#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc12-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc12-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc12-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F263 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:36b8608d9ac2537f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc13-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc13-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc13-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F264 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d905f8379d158e6b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc14-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc14-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc14-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F265 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e1feda5a781e14f1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc15-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc15-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc15-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F266 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:22ee17f152b10e5e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc16-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc16-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc16-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F267 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2a63669ff7e86cda#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc17-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc17-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc17-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F268 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2bf27d35c5c754e5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc18-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc18-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc18-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F269 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a21a3ac1e049e044#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc19-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc19-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc19-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F270 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7034d56583253283#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc20-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc20-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc20-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F271 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fe3d1cb207b5605a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc21-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc21-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc21-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F272 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f8ab319c95814878#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc103-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc103-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc103-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F273 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9d1ce8a8ff9180ab#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc104-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc104-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc104-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F274 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:cc1b050fbabbfa30#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc105-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc105-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc105-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F275 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:831a86a87d34009c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc106-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc106-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc106-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F276 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e8ce2358743dd5a5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc107-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc107-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc107-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F277 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:73d62d9b51ff77a0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc108-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc108-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc108-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F278 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:513c71f16c5bf027#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc109-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc109-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc109-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F279 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7e739f36c6f04b7b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc110-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc110-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc110-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F280 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:46bbcbdd465a442b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc111-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc111-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc111-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F281 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:aea1d8cda3bb535e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc112-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc112-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc112-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F282 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0f06a1e2cc993d59#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc113-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc113-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc113-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F283 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:d6a939a1a20381ab#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc114-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc114-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc114-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F284 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c2d6616ccc7f3672#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc115-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc115-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc115-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F285 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:487c3d95869feec8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc116-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc116-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc116-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F286 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ff526f95fb7055bb#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc117-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc117-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc117-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F287 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9128140af9713bc6#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc118-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc118-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc118-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F288 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3b79b892c8cf5df8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc119-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc119-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc119-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F289 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9aa85117e756694e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc120-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc120-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc120-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F290 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b060758adeafd5ab#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc121-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc121-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc121-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F291 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:1f6e4458327a08c2#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc122-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc122-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc122-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F292 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:682e2723dfa85101#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc123-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc123-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc123-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F293 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0d6cbe593a1ba51f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc205-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc205-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc205-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F294 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4cc73d6f5ef3e021#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc206-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc206-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc206-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F295 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f8613321974f6dac#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc207-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc207-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc207-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F296 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f9d3646445d16541#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc208-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc208-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc208-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F297 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:a057d4c0138edaac#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc209-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc209-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc209-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F298 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:43ed9e86491ee18f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc210-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc210-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc210-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F299 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:599ac562c11f3436#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc211-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc211-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc211-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F300 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:22e8f2101e38d901#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc212-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc212-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc212-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F301 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:20b84d2d00c8b93a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc213-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc213-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc213-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F302 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5947ff3e05daaa3c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc214-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc214-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc214-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F303 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:01e0f328328b1518#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc215-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc215-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc215-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F304 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8d36dc9617655eca#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc216-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc216-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc216-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F305 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b0e6a6c7f78e02c4#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc217-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc217-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc217-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F306 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0743a4347491bb09#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc218-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc218-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc218-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F307 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f5b33de43c015fa9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc219-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc219-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc219-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F308 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:59e34cdab4dd2063#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc220-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc220-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc220-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F309 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8e9b6d691c145b8b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc221-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc221-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc221-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F310 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:aef14b30c55db2b5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc222-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc222-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc222-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F311 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ba812c70086e69a1#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc223-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc223-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc223-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F312 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b6c9748b1ad364df#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc224-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc224-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc224-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

#### F313 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:24efd6d83d1f1adc#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py::test_aes_cmac[tc225-valid]`
- **Message:** _pytest.outcomes.XFailed: AES-CMAC tc225-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: AES-CMAC tc225-valid: advertised AES operation is not operational: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_wycheproof_rsa_oaep.py` (1 findings)

#### F314 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:89ab01d4f4123589`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `xfail` · **Tests covered:** 26
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_oaep.py::test_rsa_oaep[rsa_oaep_2048_sha512_224_mgf1sha1_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: RSA-OAEP SHA-512/224/SHA-1 advertised but not operational (canonical OAEP SHA-512/224/SHA-1 decrypt rejected: Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID; expected one of: CKR_OK); vector: Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID; expected one of: CKR_OK
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.


## Already documented in `docs/module-issues.md` (117 findings)

These records match an existing module-issues.md entry. Not re-listed here to avoid duplication; see `verdicts.jsonl` for individual pointers.

## Not yet classified (57 groups, DEFERRED)

Per user directive m0213-m0214, classification extension stopped. These will be classified by an in-tool workflow.

Top by size:
| Group size | Direction | Test file | Signature |
|---:|---|---|---|
| 62 | REJECT_VALID | `test_wycheproof_dsa.py` | `sha1:cb1d8836cdd9312d` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:0d176335d306bb4e` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:f9f64047072c8b19` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:1ca40f86e78c6891` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:c76b251e86058578` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:36f432e930bc9e30` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:d6bd8533ac41b713` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:aa8a77c3cb1cdc2f` |
| 33 | OTHER | `test_wycheproof_hmac.py` | `sha1:eb1051d33668cd4b` |
| 32 | REJECT_VALID | `test_wycheproof_dsa.py` | `sha1:f9722a8f3feb4a4c` |
| 32 | REJECT_VALID | `test_wycheproof_dsa.py` | `sha1:a7352e24ba90239e` |
| 16 | CLEAN_ERROR | `test_wycheproof_mlkem_encaps_modulus.py` | `sha1:50a5c09e0d86d853` |
| 12 | CLEAN_ERROR | `test_wycheproof_mlkem_encaps_modulus.py` | `sha1:edf4dd011a45aa89` |
| 5 | CLEAN_ERROR | `test_ckr_decrypt.py` | `sha1:46312e4b5ea5a115` |
| 4 | CLEAN_ERROR | `test_mech_attribute.py` | `sha1:65d174391086cadc` |
