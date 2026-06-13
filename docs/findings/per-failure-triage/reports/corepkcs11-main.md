# corepkcs11-main — Per-Failure Triage

**Effective records:** 170
**Categories:** {'UNKNOWN': 60, 'PROVIDER_BUG': 53, 'KNOWN_ISSUE': 24, 'SOFT_TOKEN_CAVEAT': 19, 'HARNESS_BUG': 14}
**Severities:** {'MEDIUM': 74, 'LOW': 74, 'INFO': 13, 'HIGH': 9}

## Findings (84)

Ordered by severity then category.

### `test_acvp_hmac.py` (2 findings)

#### F001 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:897a344a8c250aa8`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `xfail` · **Tests covered:** 118
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_hmac.py::test_acvp_hmac[HMAC-SHA2-256-2.0-tc1]`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC advertised but imported HMAC key was not accepted: key_type=0x2b: Unexpected CK_RV CKR_KEY_TYPE_INCONSISTENT; expected one of: CKR_OK; key_type=0x10: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F002 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:2256f406048ce5c7`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 30
- **Example nodeid:** `src/pkcs11_check/testcases/acvp/test_acvp_hmac.py::test_acvp_hmac[HMAC-SHA2-256-2.0-tc6]`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC advertised but imported HMAC key was not accepted: key_type=0x10: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

### `test_ckr_codes.py` (2 findings)

#### F003 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:769a3e8bc4c43e73#phase6`
- **Direction:** `WRONG_OUTPUT` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_codes.py::TestCKRPinErrors::test_ckr_pin_incorrect`
- **Message:** AssertionError: Expected CKR_PIN_INCORRECT, got CKR_OK
assert <CKR_OK: 0x00000000> == <CKR_PIN_INCORRECT: 0x000000a0>
- **Evidence:** corepkcs11 (FreeRTOS/mbedTLS embedded soft mock) returns CKR_OK for C_Login with a wrong PIN 'WRONG_PIN_XYZ_999' (test_ckr_codes.py:59-63). C_Login is a non-validating stub in this embedded mock, so any PIN is accepted. Functional severity is HIGH (auth bypass) but downgraded per the soft-token threat model: the host process already has full key access and corePKCS11's key storage/PIN enforcement is the porting PAL's responsibility, not the library's.

#### F004 [LOW/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:06d68766bd2b1536#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_codes.py::TestCKRSessionErrors::test_ckr_user_already_logged_in`
- **Message:** AssertionError: Expected CKR_USER_ALREADY_LOGGED_IN, got CKR_OK
assert <CKR_OK: 0x00000000> in (<CKR_USER_ALREADY_LOGGED_IN: 0x00000100>, <CKR_USER_TYPE_INVALID: 0x00000103>, <CKR_PIN_INCORRECT: 0x000000a0>)
- **Evidence:** corepkcs11 returns CKR_OK for a duplicate C_Login (already logged in) instead of CKR_USER_ALREADY_LOGGED_IN (test_ckr_codes.py:164). The embedded mock does not track per-token login state, so a second login is silently accepted. Minor lifecycle deviation with no security impact beyond the mock's non-enforcing login model.

### `test_ckr_fault_inject.py` (3 findings)

#### F005 [MEDIUM/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:be5f1c5b0884cd05#phase6`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_fault_inject.py::TestFaultInjection::test_inject_device_removed_on_encrypt`
- **Message:** Failed: fault-proxy C_Encrypt CKR_DEVICE_REMOVED injection: module crashed with signal 11
stdout: 
stderr:
- **Evidence:** fault-proxy.so intercepts C_Encrypt to inject CKR_DEVICE_REMOVED; the proxy shim itself crashes signal 11. The real module never sees the call (injection is handled inside the proxy). Both this injection test and the pure-delegation test crash, implicating the proxy shim, not corepkcs11.

#### F006 [MEDIUM/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:35e85d460c2b8081#phase6`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_fault_inject.py::TestFaultProxyBasic::test_proxy_encrypt_decrypt`
- **Message:** Failed: fault-proxy AES roundtrip delegation: module crashed with signal 11
stdout: 
stderr:
- **Evidence:** fault-proxy.so pure-delegation encrypt/decrypt roundtrip (NO injection env vars set) crashes signal 11. With no error injection, the proxy simply forwards to the real module; corepkcs11 does not crash on normal encrypt in any other test -> the proxy forwarding logic is the proximate cause.

#### F007 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:616589799bce55d0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_fault_inject.py::TestFaultInjection::test_inject_device_error_on_sign`
- **Message:** _pytest.outcomes.XFailed: C_GenerateKeyPair for fault-injected sign failed: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_GenerateKeyPair for fault-injected sign failed: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK. Direction = reject-valid → functional gap (LOW).

### `test_ckr_keygen.py` (3 findings)

#### F008 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:3fa56903809ca6c1`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyPairErrors::test_ec_curve_not_supported`
- **Message:** Failed: C_GenerateKeyPair(unsupported_EC_curve): got CKR_TEMPLATE_INCOMPLETE, not in acceptable set ['CKR_CURVE_NOT_SUPPORTED', 'CKR_DOMAIN_PARAMS_INVALID', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_MECHANISM_INVALID', 'CKR_FUNCTION_FAILED', 'CKR_GENERAL_ERROR', 'CKR_HOST_MEMORY', 'CKR_SESSION_HANDLE_INVA
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F009 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:bb94fc209ac3790b`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyPairErrors::test_domain_params_invalid`
- **Message:** Failed: C_GenerateKeyPair(malformed_EC_params): got CKR_TEMPLATE_INCOMPLETE, not in acceptable set ['CKR_DOMAIN_PARAMS_INVALID', 'CKR_CURVE_NOT_SUPPORTED', 'CKR_ATTRIBUTE_VALUE_INVALID', 'CKR_MECHANISM_INVALID', 'CKR_FUNCTION_FAILED', 'CKR_GENERAL_ERROR', 'CKR_HOST_MEMORY', 'CKR_SESSION_HANDLE_INVAL
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F010 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:8b191ec50a06cb3b#phase6`
- **Direction:** `REJECT_VALID` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_keygen.py::TestGenerateKeyPairErrors::test_bad_rsa_size_zero`
- **Message:** _pytest.outcomes.XFailed: C_GenerateKeyPair(invalid_key_size): rejected with CKR_MECHANISM_INVALID, spec prefers ['CKR_ATTRIBUTE_VALUE_INVALID'] [PKCS#11 v3.1 Sec.5.14.2]
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_GenerateKeyPair(invalid_key_size): rejected with CKR_MECHANISM_INVALID, spec prefers ['CKR_ATTRIBUTE_VALUE_INVALID'] [PKCS#11 v3.1 Sec.5.14.2]. Direction = reject-valid → functional gap (LOW).

### `test_ckr_object.py` (1 findings)

#### F011 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4dc1d09f70e16fed#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_object.py::TestFindObjectsErrors::test_find_with_empty_result`
- **Message:** assert <CKR_ARGUMENTS_BAD: 0x00000007> == <CKR_OK: 0x00000000>
- **Evidence:** C_FindObjectsInit returns CKR_ARGUMENTS_BAD instead of CKR_OK for a find that should return empty result. PKCS#11 spec requires C_FindObjectsInit to succeed (return CKR_OK) for any valid template, with C_FindObjects returning zero matches. corePKCS11's find path is over-strict.

### `test_ckr_priority.py` (1 findings)

#### F012 [LOW/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:58b910c96353483d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_priority.py::TestErrorPriority::test_wrong_key_type_with_nonaligned_data`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** TestErrorPriority::test_wrong_key_type_with_nonaligned_data setup uses gen_rsa_keypair without an rs.has_mechanism guard; corePKCS11 doesn't support RSA keygen, so setup returns CKR_MECHANISM_INVALID before the CKR-priority probe runs. Harness should skip when RSA keygen is unsupported.

### `test_ckr_raw_buffer.py` (2 findings)

#### F013 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:007252420215018a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestBufferTooSmall::test_digest_buffer_too_small`
- **Message:** _pytest.outcomes.XFailed: C_Digest returned CKR_OK for a 1-byte output buffer without writing past it (PKCS#11 §5.10.2 expects CKR_BUFFER_TOO_SMALL; clean return-code deviation, no buffer overflow)
- **Evidence:** Buffer-protocol deviation: C_Digest returned CKR_OK for a 1-byte output buffer without writing past it (PKCS#11 §5.10.2 expects CKR_BUFFER_TOO_SMALL; clean return-code deviation, no buffer overflow).

#### F014 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4e3b480f44467bc5#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_raw_buffer.py::TestBufferTooSmall::test_sign_buffer_too_small`
- **Message:** _pytest.outcomes.XFailed: C_GenerateKeyPair for RSA sign failed: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: C_GenerateKeyPair for RSA sign failed: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_ckr_session.py` (3 findings)

#### F015 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:d3fb319f81e6e137`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_session.py::TestLoginErrors::test_wrong_pin`
- **Message:** Failed: C_Login with a wrong PIN: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

#### F016 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:a5582b4d145cbb9e#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_session.py::TestOpenSessionErrors::test_invalid_slot_id`
- **Message:** AssertionError: Expected CKR_SLOT_ID_INVALID for bad slot, got CKR_OK
assert <CKR_OK: 0x00000000> == <CKR_SLOT_ID_INVALID: 0x00000003>
- **Evidence:** corepkcs11 returns CKR_OK for C_OpenSession on an invalid slot id 0xDEADBEEF where the spec requires CKR_SLOT_ID_INVALID (test_ckr_session.py:58-72). The embedded mock does not validate the slot id against the slot list. Input-validation gap; soft mock whose PAL presents a single fixed slot.

#### F017 [LOW/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:bfe8cd399f9534c0#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_session.py::TestLoginErrors::test_already_logged_in`
- **Message:** AssertionError: Expected CKR_USER_ALREADY_LOGGED_IN, got CKR_OK
assert <CKR_OK: 0x00000000> in (<CKR_USER_ALREADY_LOGGED_IN: 0x00000100>, <CKR_USER_TYPE_INVALID: 0x00000103>, <CKR_PIN_INCORRECT: 0x000000a0>)
- **Evidence:** corepkcs11 returns CKR_OK for a duplicate C_Login instead of CKR_USER_ALREADY_LOGGED_IN (test_ckr_session.py:109-114), the same non-enforcing-login trait as test_ckr_codes.py. The embedded mock does not track login state. Minor lifecycle deviation; clean CKR_OK, no security impact beyond the soft-token model.

### `test_ckr_sign.py` (1 findings)

#### F018 [LOW/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:3eeded3a998f9234#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_sign.py::TestSignInitErrors::test_mechanism_invalid`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** TestSignInitErrors::test_mechanism_invalid setup uses gen_rsa_keypair without an rs.has_mechanism guard; corePKCS11 doesn't advertise CKM_RSA_PKCS_KEY_PAIR_GEN, so setup returns CKR_MECHANISM_INVALID before the CKR_SIGN probe runs (3 occurrences). Harness should skip when RSA keygen is unsupported. Cohort-implicit: covers sibling tests in TestSignInitErrors using gen_rsa_keypair.

### `test_ckr_spec_compliance.py` (1 findings)

#### F019 [LOW/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:9731c762ec64919b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_spec_compliance.py::TestCKRVerifyCompliance::test_bad_signature_returns_signature_invalid`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** TestCKRVerifyCompliance::test_bad_signature_returns_signature_invalid setup uses gen_rsa_keypair without an rs.has_mechanism guard; corePKCS11 doesn't advertise CKM_RSA_PKCS_KEY_PAIR_GEN, so setup returns CKR_MECHANISM_INVALID before the CKR_VERIFY probe runs. Harness should skip when RSA keygen is unsupported.

### `test_ckr_verify.py` (1 findings)

#### F020 [LOW/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:df6eef0c62ca7655#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/ckr/test_ckr_verify.py::TestVerifyInitErrors::test_mechanism_invalid`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** TestVerifyInitErrors::test_mechanism_invalid setup uses gen_rsa_keypair without an rs.has_mechanism guard; corePKCS11 doesn't advertise CKM_RSA_PKCS_KEY_PAIR_GEN, so setup returns CKR_MECHANISM_INVALID before the CKR_VERIFY probe runs (4 occurrences). Harness should skip when RSA keygen is unsupported. Cohort-implicit: covers sibling tests in TestVerifyInitErrors using gen_rsa_keypair.

### `test_api_boundary.py` (1 findings)

#### F021 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:68480b12be837d17#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_api_boundary.py::TestZeroLengthData::test_zero_length_data[sign-ECDSA]`
- **Message:** _pytest.outcomes.XFailed: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_TEMPLATE_INCONSISTENT
- **Evidence:** Capability gap: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_TEMPLATE_INCONSISTENT. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_api_security.py` (1 findings)

#### F022 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7ae2ecd9cc2337e9#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_api_security.py::TestAccessControl::test_no_login_private_objects_invisible`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_TEMPLATE_INCOMPLETE; expected one of: CKR_OK
- **Evidence:** TestAccessControl::test_no_login_private_objects_invisible find_objects returns CKR_TEMPLATE_INCOMPLETE (1 occurrence). corePKCS11's C_FindObjectsInit requires specific template attrs (e.g., CKA_LABEL) and rejects templates missing them. Spec requires CKR_OK for any valid search template.

### `test_arithmetic_overflow.py` (1 findings)

#### F023 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:77f7c5dbb0533929`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 9
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_arithmetic_overflow.py::TestTemplateCountOverflowValidHandles::test_template_count_overflow_with_valid_object_handle[get_attribute_value-ulong_max]`
- **Message:** _pytest.outcomes.XFailed: data-object import rejected: CKR_ATTRIBUTE_VALUE_INVALID
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_cve_regression.py` (1 findings)

#### F024 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9b912f11aa3425b4#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_cve_regression.py::TestCKADeriveOnEC::test_ec_keygen_with_derive`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_TYPE_INVALID; expected one of: CKR_OK
- **Evidence:** test_ec_keygen_with_derive setup returns CKR_ATTRIBUTE_TYPE_INVALID (3 occurrences) — corePKCS11 doesn't recognize CKA_DERIVE in the EC keygen template. Cohort-implicit: covers sibling CVE regression tests using CKA_DERIVE.

### `test_ffi_length_boundary.py` (5 findings)

#### F025 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:24befcfde05f1e85`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_digest_isize_boundary[isize_max]`
- **Message:** Failed: C_Digest(SHA256, ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F026 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:ce03c1095ecbf8fe`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_digest_isize_boundary[isize_max_plus_1]`
- **Message:** Failed: C_Digest(SHA256, ulDataLen=0x8000000000000000): module crashed with signal 11
stdout: 
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F027 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:eeee3f2a70e072e8`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[digest_update-isize_max]`
- **Message:** Failed: C_DigestUpdate(ulDataLen=0x7fffffffffffffff): module crashed with signal 11
stdout: TARGET:C_DigestUpdate
LEN:9223372036854775807
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F028 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:936b34a9d5aa131f`
- **Direction:** `CRASH` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxUpdateLength::test_update_isize_data_len[digest_update-isize_max_plus_1]`
- **Message:** Failed: C_DigestUpdate(ulDataLen=0x8000000000000000): module crashed with signal 11
stdout: TARGET:C_DigestUpdate
LEN:9223372036854775808
stderr:
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

#### F029 [MEDIUM/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:333b358b68fd9481`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_length_boundary.py::TestIsizeMaxDataLength::test_verify_isize_data_len[isize_max]`
- **Message:** _pytest.outcomes.XFailed: HMAC key import rejected: CKR_MECHANISM_INVALID
- **Evidence:** UB-provoked crash on absurd length. Spec places burden on caller, but robust modules validate. Universal across soft-tokens.

### `test_ffi_null_pointer.py` (5 findings)

#### F030 [LOW/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:4e46af52bdd6c27e#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestNullDataUpdate::test_null_data_update[C_SignUpdate]`
- **Message:** Failed: C_SignUpdate(data=NULL, data_len=32): subprocess failed with exit code 1
stdout: P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"C
- **Evidence:** Not a real accept-invalid: the crash-isolated child setup calls import_secret_key (C_CreateObject CKK_GENERIC_SECRET) which corepkcs11 cleanly rejects with CKR_MECHANISM_INVALID, and the child's expect_rv(CKR_OK) raises CkrAssertionError (subprocess exit 1) before the C_SignUpdate(NULL,32) probe is ever reached (test_ffi_null_pointer.py:185-201 setup body). The module behaved correctly; the classifier flagged exit-1 as ACCEPT_INVALID. corepkcs11's non-operational GENERIC_SECRET import is already

#### F031 [LOW/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:cf512e39956d81e7#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestNullDataUpdate::test_null_data_update[C_VerifyUpdate]`
- **Message:** Failed: C_VerifyUpdate(data=NULL, data_len=32): subprocess failed with exit code 1
stdout: P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":
- **Evidence:** Same as the C_SignUpdate sibling: the child import_secret_key setup is rejected by corepkcs11 with CKR_MECHANISM_INVALID and the child raises before the C_VerifyUpdate(NULL,32) probe runs (test_ffi_null_pointer.py:214-230). Exit-1 was misclassified as ACCEPT_INVALID; the module produced a clean reject of the setup, not acceptance of a NULL data pointer.

#### F032 [LOW/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:56326f78c0973f72#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestNullOutputFinal::test_null_output_final[C_SignFinal]`
- **Message:** Failed: C_SignFinal(output=NULL, length_query): subprocess failed with exit code 1
stdout: P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":
- **Evidence:** Same harness setup failure: corepkcs11 rejects the GENERIC_SECRET import with CKR_MECHANISM_INVALID and the child exits 1 before the C_SignFinal(NULL,len) length-query probe runs (test_ffi_null_pointer.py:424-449). Not a real acceptance of a NULL output buffer; the module cleanly rejected the setup.

#### F033 [LOW/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:0e53333511836258#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestNullDataOneShot::test_null_data_oneshot[C_Sign]`
- **Message:** Failed: C_Sign(data=NULL, data_len=32): subprocess failed with exit code 1
stdout: P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"
- **Evidence:** Same setup failure pattern: child import_secret_key rejected by corepkcs11 (CKR_MECHANISM_INVALID) before the C_Sign(NULL,32) one-shot probe runs (test_ffi_null_pointer.py:901-921). Exit-1 misclassified as ACCEPT_INVALID; module produced a clean setup reject.

#### F034 [LOW/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:3a64f9c54086eb4b#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_ffi_null_pointer.py::TestNullDataOneShot::test_null_data_oneshot[C_Verify]`
- **Message:** Failed: C_Verify(data=NULL, data_len=32): subprocess failed with exit code 1
stdout: P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_O
- **Evidence:** Same setup failure pattern: GENERIC_SECRET import rejected by corepkcs11 (CKR_MECHANISM_INVALID) before the C_Verify(NULL,32) probe runs (test_ffi_null_pointer.py:934-951). Exit-1 misclassified as ACCEPT_INVALID; the module cleanly rejected setup.

### `test_nonce_quality.py` (1 findings)

#### F035 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:fbc6a940ff634520#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_nonce_quality.py::TestECDSANonceReuse::test_nonce_reuse_p256`
- **Message:** _pytest.outcomes.XFailed: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_TEMPLATE_INCONSISTENT
- **Evidence:** Capability gap: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_TEMPLATE_INCONSISTENT. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_secret_key_value_len.py` (1 findings)

#### F036 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e1fb1b29b3cd720a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/security/test_secret_key_value_len.py::TestExistingSecretKeyValueLen::test_copy_secret_key_with_oversized_value_len_does_not_crash`
- **Message:** _pytest.outcomes.XFailed: secret-key import rejected: CKR_MECHANISM_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: secret-key import rejected: CKR_MECHANISM_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_access.py` (1 findings)

#### F037 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:bb707fc14d4c942f#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_access.py::TestLoginStates::test_public_session_no_private_keys`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_TEMPLATE_INCOMPLETE; expected one of: CKR_OK
- **Evidence:** TestLoginStates::test_public_session_no_private_keys find_objects returns CKR_TEMPLATE_INCOMPLETE (1 occurrence). Same corePKCS11 find-objects over-strict-template trait as bucket 29.

### `test_access_levels.py` (1 findings)

#### F038 [HIGH/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:8dc6852b4f52a054`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_access_levels.py::TestUserSessionCapabilities::test_user_cannot_login_as_so`
- **Message:** Failed: C_Login(SO) while a USER session is logged in: accepted invalid (CKR_OK) -- must reject
- **Evidence:** Bleichenbauer-class: accepts invalid PKCS#1 v1.5 ciphertext. Universal soft-token mitigation matter; severity is HIGH functionally but downgraded to SOFT_TOKEN_CAVEAT (host already has key access).

### `test_aead.py` (1 findings)

#### F039 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f541ede364381d1a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_aead.py::TestAESGCMCrossVerify::test_gcm_tampered_tag_rejected`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK
- **Evidence:** TestAESGCMCrossVerify::test_gcm_tampered_tag_rejected setup returns CKR_ARGUMENTS_BAD (2 occurrences) — corePKCS11 AES import limitation blocks AEAD setup. Cohort-implicit: covers sibling AES-GCM tests with same import setup.

### `test_always_authenticate.py` (1 findings)

#### F040 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0b0d06a3f5ed3644#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_always_authenticate.py::TestAlwaysAuthenticateEnforcement::test_context_specific_login_without_active_op_rejected`
- **Message:** Failed: Module accepted CKU_CONTEXT_SPECIFIC login outside any active operation — spec requires CKR_OPERATION_NOT_INITIALIZED.
- **Evidence:** corePKCS11 accepts C_Login(CKU_CONTEXT_SPECIFIC) outside any active operation, returning CKR_OK. PKCS#11 v3.1 §5.5 requires CKR_OPERATION_NOT_INITIALIZED (or CKR_USER_NOT_LOGGED_IN) when context-specific login is called without an active operation. Accepting it is a spec violation that weakens the CKA_ALWAYS_AUTHENTICATE re-auth semantics.

### `test_attribute_enforcement.py` (1 findings)

#### F041 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:671ce0ee5071121e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_attribute_enforcement.py::TestKeyGenMechanism::test_imported_key_has_unavailable`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK
- **Evidence:** TestKeyGenMechanism::test_imported_key_has_unavailable setup returns CKR_ARGUMENTS_BAD (2 occurrences) — corePKCS11 AES import limitation. Cohort-implicit: covers sibling imported-key attribute tests.

### `test_attribute_invariants.py` (1 findings)

#### F042 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0a293d1771dda4ea#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_attribute_invariants.py::TestDerivedAttributeInvariants::test_imported_aes_key_reports_not_local_no_key_gen_mechanism`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK
- **Evidence:** TestDerivedAttributeInvariants::test_imported_aes_key_reports_not_local_no_key_gen_mechanism setup returns CKR_ARGUMENTS_BAD (1 occurrence) — corePKCS11 AES import limitation. Setup fails before the derived-attribute probe runs.

### `test_buffers.py` (4 findings)

#### F043 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b089026884f14275#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_buffers.py::TestOutputBufferEdgeCases::test_digest_final_buffer_too_small_then_correct`
- **Message:** AssertionError: After CKR_BUFFER_TOO_SMALL, pulSize must equal required size; got 8, expected 32
assert 8 == 32
 +  where 8 = c_ulong(8).value
- **Evidence:** After CKR_BUFFER_TOO_SMALL, C_DigestFinal reports pulSize=8 when the actual required size is 32. PKCS#11 v3.1 §5.2 requires the true required length on CKR_BUFFER_TOO_SMALL; reporting 8 makes the caller size the buffer wrong. Real buffer-size-protocol bug.

#### F044 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4187db614906c3b3#phase6`
- **Direction:** `OTHER` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_buffers.py::TestOutputBufferEdgeCases::test_digest_final_preserves_state_across_multiple_retries`
- **Message:** AssertionError: Retry #1: pulSize must be 32, got 1
assert 1 == 32
 +  where 1 = c_ulong(1).value
- **Evidence:** C_DigestFinal multi-retry returns pulSize=1 when 32 is expected. The required-size value changes across retries and is wrong — caller cannot reliably size the buffer. Buffer-size-protocol bug.

#### F045 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:aea32d653a820632#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_buffers.py::TestOutputBufferEdgeCases::test_digest_final_with_oversize_buffer_writes_actual_size`
- **Message:** AssertionError: C_DigestFinal with 1024-byte buffer: 0x00000150
assert 336 == <CKR_OK: 0x00000000>
- **Evidence:** C_DigestFinal with a 1024-byte buffer returns CKR_BUFFER_TOO_SMALL (0x150) when the output (32 bytes) easily fits. The function should return CKR_OK and write the digest; instead it rejects a clearly-adequate buffer. Buffer-size-protocol bug.

#### F046 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c04a60ab514a9021#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_buffers.py::TestKeyImportBufferSizes::test_aes_128`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK
- **Evidence:** AES key import returns CKR_ARGUMENTS_BAD (4 occurrences) — documented corePKCS11 AES secret-key import limitation. Test setup (gen_aes_key or import_secret_key) fails before the buffer-size probe runs. Cohort-implicit: covers sibling TestKeyImportBufferSizes tests with same AES import setup.

### `test_crossverify.py` (1 findings)

#### F047 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:f22d1a5c1c1b32f7#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_crossverify.py::TestECDSACrossVerify::test_ecdsa_p256`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK
- **Evidence:** TestECDSACrossVerify::test_ecdsa_p256 setup returns CKR_ARGUMENTS_BAD (3 occurrences) — corePKCS11 EC secret/key import limitation blocks the cross-verify setup. Cohort-implicit: covers sibling ECDSA cross-verify tests.

### `test_crossverify_extended.py` (1 findings)

#### F048 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:431085c68fe4bd6d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_crossverify_extended.py::TestAESCBCCrossVerify::test_aes_cbc_encrypt_crossverify`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK
- **Evidence:** TestAESCBCCrossVerify::test_aes_cbc_encrypt_crossverify setup returns CKR_ARGUMENTS_BAD (2 occurrences) — corePKCS11 AES import limitation. Cohort-implicit: covers sibling AES-CBC cross-verify tests.

### `test_fuzz.py` (2 findings)

#### F049 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:db7c4176b70bea59#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_fuzz.py::TestHMACFuzz::test_hmac_sha256_cross_verify`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC advertised but fuzz HMAC key import is not operational: CKR_ARGUMENTS_BAD
Falsifying example: test_hmac_deterministic(
    self=<pkcs11_check.testcases.test_fuzz.TestHMACFuzz object at 0x7fb5a800ac10>,
    p11_raw_session=RawSession(raw=<pkcs11_check.raw.api.Raw
- **Evidence:** Capability gap: SHA256_HMAC advertised but fuzz HMAC key import is not operational: CKR_ARGUMENTS_BAD
Falsifying example: test_hmac_deterministic(
    self=<pkcs11_check.testcases.test_fuzz.TestHMACFuzz object at 0x7fb5a800ac10>,
    p11_raw_session=RawSes. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

#### F050 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b46e50a9169c8ccf#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_fuzz.py::TestECDSAFuzz::test_ecdsa_sign_verify_roundtrip`
- **Message:** _pytest.outcomes.XFailed: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_TEMPLATE_INCONSISTENT
Falsifying example: test_ecdsa_sign_verify_roundtrip(
    self=<pkcs11_check.testcases.test_fuzz.TestECDSAFuzz object at 0x7fb5a800ad50>,
    p11_raw_session=RawSession(raw=<pkcs
- **Evidence:** Capability gap: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_TEMPLATE_INCONSISTENT
Falsifying example: test_ecdsa_sign_verify_roundtrip(
    self=<pkcs11_check.testcases.test_fuzz.TestECDSAFuzz object at 0x7fb5a800ad50>,
    p1. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_generic_secret.py` (1 findings)

#### F051 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:c6f1850d09b6a481#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_generic_secret.py::TestGenericSecretHMAC::test_hmac_with_imported_generic_secret`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK
- **Evidence:** TestGenericSecretHMAC::test_hmac_with_imported_generic_secret setup returns CKR_ARGUMENTS_BAD (1 occurrence) — corePKCS11 doesn't support generic-secret import (documented imported-secret-key limitation extends to CKK_GENERIC_SECRET).

### `test_interop.py` (1 findings)

#### F052 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:2ac5c959f3a2fd4e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_interop.py::TestECDSAInterop::test_ecdsa_sign_p11_verify_crypto`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** TestECDSAInterop setup returns CKR_MECHANISM_INVALID (4 occurrences). corePKCS11 doesn't support the ECDSA interop mechanism used by the test (likely CKM_ECDSA_KEY_PAIR_GEN or CKM_ECDSA). Cohort-implicit: covers sibling ECDSA interop tests in this file.

### `test_kdf.py` (1 findings)

#### F053 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9dbfa680c5e72fb2#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_kdf.py::TestKeyDeriveSoftware::test_derive_from_digest`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK
- **Evidence:** KDF derive-from-digest setup returns CKR_ARGUMENTS_BAD (4 occurrences) — corePKCS11 AES secret-key import limitation blocks derive-key setup. Cohort-implicit: covers sibling KDF tests with same AES key import setup.

### `test_key_flags.py` (1 findings)

#### F054 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:217ddf1c0253ff5a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_key_flags.py::TestLocalFlag::test_imported_key_is_not_local`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK
- **Evidence:** TestLocalFlag::test_imported_key_is_not_local setup import_secret_key returns CKR_ARGUMENTS_BAD (1 occurrence) — corePKCS11 AES import limitation blocks the CKA_LOCAL flag test setup.

### `test_key_sizes.py` (1 findings)

#### F055 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e5434c78b21d3b68#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_key_sizes.py::TestAESKeySizes::test_aes_import_export[128]`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK
- **Evidence:** TestAESKeySizes::test_aes_import_export returns CKR_ARGUMENTS_BAD (3 occurrences) — documented corePKCS11 AES import limitation. Cohort-implicit: covers sibling AES key-size tests.

### `test_keymgmt.py` (1 findings)

#### F056 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:112fa6bec6931184#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_keymgmt.py::TestKeyImport::test_import_aes_key`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK
- **Evidence:** test_import_aes_key returns CKR_ARGUMENTS_BAD (3 occurrences) — documented corePKCS11 AES secret-key import limitation. Cohort-implicit: covers sibling AES keymgmt tests.

### `test_mech_attribute.py` (1 findings)

#### F057 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:3cc96b7c060acd53#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_attribute.py::TestKeyAttributes::test_key_type_matches_template[ECDSA_KEY_PAIR_GEN]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_KEY_PAIR_GEN keypair rejected at runtime: CKR_TEMPLATE_INCONSISTENT
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ECDSA_KEY_PAIR_GEN keypair rejected at runtime: CKR_TEMPLATE_INCONSISTENT. Direction = reject-valid → functional gap (LOW).

### `test_mech_keygen.py` (1 findings)

#### F058 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:49635c1a7e8b2ced#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_keygen.py::TestMechKeygen::test_generate_key[ECDSA_KEY_PAIR_GEN]`
- **Message:** _pytest.outcomes.XFailed: ECDSA_KEY_PAIR_GEN keypair rejected at runtime: CKR_TEMPLATE_INCONSISTENT
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ECDSA_KEY_PAIR_GEN keypair rejected at runtime: CKR_TEMPLATE_INCONSISTENT. Direction = reject-valid → functional gap (LOW).

### `test_mech_negative.py` (1 findings)

#### F059 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:58b031b47673d7a0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_negative.py::TestWrongKeyType::test_registry_sign_wrong_key_type[AES_CMAC]`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** TestWrongKeyType::test_registry_sign_wrong_key_type[AES_CMAC] returns CKR_MECHANISM_INVALID (2 occurrences) — corePKCS11 doesn't advertise AES_CMAC (no AES mechanisms at all), so the wrong-key-type probe can't be exercised. Cohort-implicit: covers sibling wrong-key-type tests for unsupported mechanisms.

### `test_mech_sign.py` (2 findings)

#### F060 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:e4fe107eafc55eb3`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignKAT::test_kat_vector[SHA256_HMAC]`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC:kat-sign: advertised but not operational (CKR_KEY_TYPE_INCONSISTENT)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F061 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b44bac21308fe9f4#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_mech_sign.py::TestMechSignRoundtrip::test_roundtrip[ECDSA]`
- **Message:** _pytest.outcomes.XFailed: ECDSA keypair rejected at runtime: CKR_TEMPLATE_INCONSISTENT
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: ECDSA keypair rejected at runtime: CKR_TEMPLATE_INCONSISTENT. Direction = reject-valid → functional gap (LOW).

### `test_multipart_streaming.py` (1 findings)

#### F062 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:ad96e5a3de17c081#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_multipart_streaming.py::TestMultipartSign::test_hmac_large_data_crossverify`
- **Message:** _pytest.outcomes.XFailed: SHA256_HMAC advertised but setup key import is not operational: CKR_MECHANISM_INVALID
- **Evidence:** Capability gap: SHA256_HMAC advertised but setup key import is not operational: CKR_MECHANISM_INVALID. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_object.py` (1 findings)

#### F063 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:90abd5cf8cbb29b3#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_object.py::TestSessionObjects::test_empty_search_returns_empty`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK
- **Evidence:** C_FindObjectsInit returns CKR_ARGUMENTS_BAD instead of CKR_OK for an empty-result search (3 occurrences). Spec requires CKR_OK with C_FindObjects returning zero matches. corePKCS11's find path is over-strict. Cohort-implicit: covers sibling search tests in this file.

### `test_object_search_patterns.py` (1 findings)

#### F064 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b5fadb898b9b9107#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_object_search_patterns.py::TestSearchByID::test_no_match_by_wrong_id`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_TEMPLATE_INCOMPLETE; expected one of: CKR_OK
- **Evidence:** TestSearchByID::test_no_match_by_wrong_id find_objects returns CKR_TEMPLATE_INCOMPLETE (1 occurrence). corePKCS11's C_FindObjectsInit requires specific template attrs and rejects templates missing them. Spec requires CKR_OK for any valid search template.

### `test_operation_state.py` (2 findings)

#### F065 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:0e746bb2115e13a0#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_state.py::TestDigestStateRoundTrip::test_digest_state_same_session`
- **Message:** Failed: Subprocess failed: stdout='REFERENCE:265f60b1719678c5cbe44047c642e0a83e24ff9e010b67f916008ddd0906dd3f\nSINGLESHOT_OK:265f60b1719678c5cbe44047c642e0a83e24ff9e010b67f916008ddd0906dd3f\nP11_RV_TRACE_JSON:[{"i":0,"fn":"C_DigestInit","mech":592,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_DigestUpda
- **Evidence:** TestDigestStateRoundTrip::test_digest_state_same_session subprocess fails — corePKCS11's C_GetOperationState/C_SetOperationState path doesn't return the spec-mandated CKR_STATE_UNSAVEABLE for unsaveable digest state, breaking the test's state-save/restore round-trip.

#### F066 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:4eef6a6c0df9ed12#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_state.py::TestDigestStateRoundTrip::test_digest_state_cross_session`
- **Message:** Failed: Subprocess failed: stdout='P11_RV_TRACE_JSON:[{"i":0,"fn":"C_DigestInit","mech":592,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_DigestUpdate","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"C_CloseSession","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":3,"fn":"C_Finalize","mech":null,"rv":0,"
- **Evidence:** TestDigestStateRoundTrip::test_digest_state_cross_session subprocess fails — same operation-state limitation as same-session variant; cross-session restore is even less likely to be supported in a minimal embedded module.

### `test_operation_termination.py` (1 findings)

#### F067 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7f78044befcdc013#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_operation_termination.py::test_c_verify_terminates_after_rejected_ecdsa_signature`
- **Message:** _pytest.outcomes.XFailed: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_TEMPLATE_INCOMPLETE
- **Evidence:** Capability gap: EC_KEY_PAIR_GEN advertised but keypair generation is not operational: CKR_TEMPLATE_INCOMPLETE. Mechanism advertised but not operational — REJECT_VALID direction (functional gap, not a security break).

### `test_profiles.py` (1 findings)

#### F068 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:18bf5ae1551be719#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 4
- **Example nodeid:** `src/pkcs11_check/testcases/test_profiles.py::TestProfileObjects::test_profile_object_enumeration`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_TEMPLATE_INCOMPLETE; expected one of: CKR_OK
- **Evidence:** CKO_PROFILE object enumeration returns CKR_TEMPLATE_INCOMPLETE (4 occurrences). corePKCS11 doesn't support v3.0 profile objects — they're a v3.0+ concept and corePKCS11 is v2.40. Advertised-but-not-operational capability gap. Cohort-implicit: covers sibling profile tests.

### `test_protocol_edge_cases.py` (1 findings)

#### F069 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:78b31179a0508188#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_protocol_edge_cases.py::TestResourceExhaustion::test_generate_random_large`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **Evidence:** TestResourceExhaustion::test_generate_random_large C_GenerateRandom(1MB) returns CKR_FUNCTION_FAILED (1 occurrence). corePKCS11's C_GenerateRandom doesn't handle large requests. Note: wolfpkcs11 has the same limitation — likely a shared mbedtls RNG constraint, but still a real deviation.

### `test_rng.py` (1 findings)

#### F070 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:96a295bc0efdc51b#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 3
- **Example nodeid:** `src/pkcs11_check/testcases/test_rng.py::TestRNGStatistical::test_bit_frequency`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **Evidence:** TestRNGStatistical::test_bit_frequency setup C_GenerateRandom returns CKR_FUNCTION_FAILED (3 occurrences). corePKCS11's C_GenerateRandom fails for the requested size. Cohort-implicit: covers sibling RNG statistical tests requesting similar sizes.

### `test_ro_session.py` (1 findings)

#### F071 [LOW/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:410a4ba782f5863e#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_ro_session.py::TestROSessionOperations::test_verify_in_ro_session`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** TestROSessionOperations::test_verify_in_ro_session setup calls gen_rsa_keypair without an rs.has_mechanism guard; corePKCS11 doesn't support RSA keygen, so setup returns CKR_MECHANISM_INVALID before the RO-session verify probe runs. Harness should skip when RSA keygen is unsupported.

### `test_rsa_key_import.py` (1 findings)

#### F072 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:5ae97166d85ae493#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_rsa_key_import.py::TestRSAPrivateKeyImport::test_import_rsa_private_key`
- **Message:** _pytest.outcomes.XFailed: RSA private-key import with the requested attributes is not operational: CKR_ATTRIBUTE_TYPE_INVALID
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: RSA private-key import with the requested attributes is not operational: CKR_ATTRIBUTE_TYPE_INVALID. Direction = reject-valid → functional gap (LOW).

### `test_search.py` (1 findings)

#### F073 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:9b1093e5cfd1f26a#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_search.py::TestObjectSearch::test_find_nonexistent_returns_empty`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK
- **Evidence:** TestObjectSearch::test_find_nonexistent_returns_empty find_objects returns CKR_ARGUMENTS_BAD (1 occurrence). corePKCS11's C_FindObjectsInit rejects a valid template that should return an empty result. Spec requires CKR_OK with C_FindObjects returning zero matches.

### `test_sensitivity.py` (1 findings)

#### F074 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:10986f50fca03c1c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 2
- **Example nodeid:** `src/pkcs11_check/testcases/test_sensitivity.py::TestSensitiveKeyValue::test_sensitive_value_not_copied_on_rejected_get_attribute`
- **Message:** _pytest.outcomes.XFailed: Cannot import sensitive AES key for mixed-attribute probe: Unexpected CK_RV CKR_ATTRIBUTE_TYPE_INVALID; expected one of: CKR_OK
- **Evidence:** Clean CKR rejection of advertised-mechanism variant: Cannot import sensitive AES key for mixed-attribute probe: Unexpected CK_RV CKR_ATTRIBUTE_TYPE_INVALID; expected one of: CKR_OK. Direction = reject-valid → functional gap (LOW).

### `test_session_edge_cases.py` (1 findings)

#### F075 [LOW/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:b2aaf8f2ce4306d8#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_session_edge_cases.py::TestSoftHSM2IssueRegressions::test_rsa_keygen_minimum_size`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **Evidence:** TestSoftHSM2IssueRegressions::test_rsa_keygen_minimum_size calls gen_rsa_keypair without an rs.has_mechanism guard; corePKCS11 doesn't support RSA keygen, so it returns CKR_MECHANISM_INVALID. Test should skip via rs.has_mechanism('RSA_PKCS_KEY_PAIR_GEN').

### `test_session_state_machine.py` (1 findings)

#### F076 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:b481c18285e6cd60#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_session_state_machine.py::TestLoginStateTransitions::test_open_session_is_public`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_TEMPLATE_INCOMPLETE; expected one of: CKR_OK
- **Evidence:** TestLoginStateTransitions::test_open_session_is_public find_objects returns CKR_TEMPLATE_INCOMPLETE (1 occurrence). corePKCS11's C_FindObjectsInit requires specific template attrs and rejects templates missing them. Setup fails before the login-state probe runs.

### `test_sign.py` (1 findings)

#### F077 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:eab836de8e92c355#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 6
- **Example nodeid:** `src/pkcs11_check/testcases/test_sign.py::TestECDSASignature::test_ec_generate_keypair`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_TEMPLATE_INCOMPLETE; expected one of: CKR_OK
- **Evidence:** EC keypair generation returns CKR_TEMPLATE_INCOMPLETE (6 occurrences). corePKCS11 requires specific template attributes (CKA_LABEL mandated) that the test's default EC keypair template may not provide; documented 'CKA_LABEL mandatory' trait. Cohort-implicit: covers sibling EC sign tests with same keypair-gen setup.

### `test_subprocess_safety.py` (2 findings)

#### F078 [MEDIUM/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7193bf93756c9c47#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_subprocess_safety.py::TestLibraryReload::test_reload_cycle_5x`
- **Message:** _pytest.outcomes.XFailed: Module fails reload cycle (rc=1): P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,"fn":"C_GetSlotList","mech":null,"rv":0,"
- **Evidence:** Library reload cycle fails (rc=1) on corepkcs11. Module cannot survive C_Initialize/Finalize cycles reliably — affects long-running daemons.

#### F079 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:977ec011d482d488#phase6`
- **Direction:** `ACCEPT_INVALID` · **Outcome:** `xfail` · **Tests covered:** 1
- **Example nodeid:** `src/pkcs11_check/testcases/test_subprocess_safety.py::TestSessionObjectProcessIsolation::test_session_object_not_visible_to_other_process`
- **Message:** _pytest.outcomes.XFailed: session-object setup rejected before cross-process isolation could be tested: FATAL:Parent_CreateObject:0x00000013
P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Initialize","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":1,"fn":"C_GetSlotList","mech":null,"rv":0,"rv_name":"CKR_OK"},{"i":2,
- **Evidence:** Capability gap: corepkcs11 rejects session-object setup with FATAL:Parent_CreateObject:0x00000013 (CKR_ATTRIBUTE_TYPE_INVALID equivalent) before cross-process isolation can be tested.

### `test_wycheproof.py` (2 findings)

#### F080 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:83ffbb1685248e71`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 504
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP384Wycheproof::test_ecdsa_p384_sha384_verify[tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: ECDSA:key-import: advertised but not operational (secp384r1: CKR_FUNCTION_FAILED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

#### F081 [LOW/SOFT_TOKEN_CAVEAT] — 📚 DOCS_ONLY
- **Signature:** `sha1:cf179962bfc36f30#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 346
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py::TestECDSAP256Wycheproof::test_ecdsa_p256_sha256_verify[tc139-invalid]`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_MEMORY; expected one of: CKR_OK
- **Evidence:** corepkcs11 returns CKR_DEVICE_MEMORY on ECDSA-P256 wycheproof verify vector import (346 occurrences). The docker-target generic PAL has finite in-memory capacity and corePKCS11's internal object table is small; large KAT suites exhaust storage during public-key import. Documented storage-model trait (module-issues.md corePKCS11 section).

### `test_wycheproof_ecdsa.py` (1 findings)

#### F082 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:7479143fdb6f6bf8`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `xfail` · **Tests covered:** 8254
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py::test_ecdsa_wycheproof[ecdsa_brainpoolP224r1_sha224_test.json:tc1-valid]`
- **Message:** _pytest.outcomes.XFailed: ECDSA:key-import: advertised but not operational (brainpoolp224r1: CKR_FUNCTION_FAILED)
- **Evidence:** Mechanism advertised but not operational — clean refusal. Per severity-direction principle, reject-valid is functional (LOW), not oracle/forgery.

### `test_wycheproof_rsa_decrypt.py` (1 findings)

#### F083 [LOW/HARNESS_BUG] — 🔧 HARNESS_FIX
- **Signature:** `sha1:f1df632f37b9566c#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 201
- **Example nodeid:** `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_decrypt.py::test_rsa_pkcs1_decrypt[rsa_pkcs1_2048_test.json:tc1-valid]`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_TYPE_INVALID; expected one of: CKR_OK
- **Evidence:** RSA private key import via import_rsa_private_key_negotiated returns CKR_ATTRIBUTE_TYPE_INVALID (201 occurrences) — corePKCS11 doesn't recognize CKA_MODULUS/CKA_PRIVATE_EXPONENT etc. The test's _skip_or_xfail_rsa_pkcs1_private_import_reject xfail list does not include CKR_ATTRIBUTE_TYPE_INVALID, so the rejection is re-raised instead of xfailed. Harness should add this CKR for modules lacking RSA private-key import support.

### `test_core_ops.py` (1 findings)

#### F084 [LOW/PROVIDER_BUG] — 📨 PROVIDER_REPORT
- **Signature:** `sha1:191aa63219c99c2d#phase6`
- **Direction:** `CLEAN_ERROR` · **Outcome:** `failure` · **Tests covered:** 9
- **Example nodeid:** `src/pkcs11_check/testcases/x509/test_core_ops.py::TestCertificateImport::test_import_der_certificate`
- **Message:** pkcs11_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_TYPE_INVALID; expected one of: CKR_OK
- **Evidence:** CKO_CERTIFICATE import returns CKR_ATTRIBUTE_TYPE_INVALID (9 occurrences). corePKCS11 doesn't recognize CKA_CERTIFICATE_TYPE / CKA_VALUE on cert templates — minimal embedded implementation has no certificate-object support. Advertised-but-not-operational capability gap.


## Already documented in `docs/module-issues.md` (24 findings)

These records match an existing module-issues.md entry. Not re-listed here to avoid duplication; see `verdicts.jsonl` for individual pointers.

## Not yet classified (60 groups, DEFERRED)

Per user directive m0213-m0214, classification extension stopped. These will be classified by an in-tool workflow.

Top by size:
| Group size | Direction | Test file | Signature |
|---:|---|---|---|
| 486 | CLEAN_ERROR | `test_wycheproof_ecdsa.py` | `sha1:367199f314759f8c` |
| 146 | REJECT_VALID | `test_wycheproof_ecdsa.py` | `sha1:49ddcfc51ccc4a3e` |
| 74 | CLEAN_ERROR | `test_limbo_import.py` | `sha1:3e852d011706bdf5` |
| 19 | CLEAN_ERROR | `test_object_visibility.py` | `sha1:f55462d993361b3a` |
| 2 | CLEAN_ERROR | `test_ckr_keygen.py` | `sha1:d103f32ee00a44d9` |
| 2 | CLEAN_ERROR | `test_ckr_raw_buffer.py` | `sha1:f3cf0c7b8162f006` |
| 2 | OTHER | `test_remaining_gaps.py` | `sha1:7dcc77e89096e0cb` |
| 2 | OTHER | `test_attributes.py` | `sha1:5dd55e70e41255dd` |
| 1 | OTHER | `test_ckr_raw_buffer.py` | `sha1:ef9b3f8b897ba237` |
| 1 | OTHER | `test_ckr_raw_buffer.py` | `sha1:a06b6a7be27adb2a` |
| 1 | OTHER | `test_secret_key_value_len.py` | `sha1:ad1a6eade7ffe66d` |
| 1 | CLEAN_ERROR | `test_digest.py` | `sha1:1c6e4bf18716696a` |
| 1 | OTHER | `test_mech_flags.py` | `sha1:e108b5e224a6b4b7` |
| 1 | OTHER | `test_mech_flags.py` | `sha1:623a406b8c2301cc` |
| 1 | CLEAN_ERROR | `test_operation_termination.py` | `sha1:8e24e3750d1fb37e` |
