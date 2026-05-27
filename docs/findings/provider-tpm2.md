# Findings: `tpm2`

Failures **213** · file-crashes **0** · classes **104** (sum 213). Root causes: [catalog.md](catalog.md); raw: [failure-inventory.json](failure-inventory.json).

## Crash (signal) (4)

- **[2]** `TestIsizeMaxDataLength::test_digest_isize_boundary` — C_Digest(SHAN, ulDataLen=H): module crashed with signal N
- **[1]** `TestArgsBadNullPointers::test_digest_init_null_mechanism` — C_DigestInit(NULL mech): module crashed with signal N
- **[1]** `TestNullMechanismInit::test_null_mechanism_init` — C_DigestInit(mechanism=NULL): module crashed with signal N

## Abort (exit code) (2)

- **[1]** `TestArgsBadNullPointers::test_generate_key_null_mechanism` — C_GenerateKey(NULL mech): subprocess failed with exit code N
- **[1]** `TestArgsBadNullPointers::test_wrap_key_null_mechanism` — C_WrapKey(NULL mech): subprocess failed with exit code N

## Wrong CK_RV (82)

- **[3]** `TestEcPointValidation::test_ecdh_invalid_point` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **[1]** `TestDataObjectCreate::test_create_data_object_empty_value` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **[1]** `TestCKRMechanismErrors::test_ckr_mechanism_invalid` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestCKRDataErrors::test_ckr_data_len_range_ecb` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestCKRAttributeErrors::test_ckr_attribute_sensitive` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestCKRAttributeErrors::test_ckr_attribute_type_invalid` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestCKRObjectErrors::test_ckr_object_handle_invalid_after_destroy` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestDeriveKeyErrors::test_mechanism_invalid` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestGetAttributeErrors::test_sensitive_value` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestGetAttributeErrors::test_destroyed_handle` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestCopyObjectErrors::test_copy_destroyed_handle` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestDestroyObjectErrors::test_destroy_already_destroyed` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestErrorPriority::test_destroyed_handle_with_wrong_mechanism` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestErrorPriority::test_bad_mechanism_with_bad_key_size` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestSignInitErrors::test_key_type_inconsistent` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestCKRMechanismCompliance::test_sha256_as_encrypt_returns_mechanism_invalid` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestCKRMechanismCompliance::test_non_aligned_ecb_returns_data_len_range` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestCKRAttributeCompliance::test_sensitive_value_returns_attribute_sensitive` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestCKRObjectCompliance::test_destroyed_handle_returns_object_handle_invalid` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestCKRMultipartCompliance::test_aes_cbc_multipart_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestVerifyInitErrors::test_key_type_inconsistent` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestDeprecatedMechanismOperation::test_deprecated_sign_operation` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **[1]** `TestPssSaltLength::test_pss_zero_salt_length` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **[1]** `TestPssSaltLength::test_pss_excessive_salt_length` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **[1]** `TestRsaOaepSha1Mgf::test_rsa_oaep_sha1_mgf` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **[1]** `TestRsaPssMd5Hash::test_rsa_pss_md5_hash` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **[1]** `TestCbcIvAllZeros::test_cbc_iv_all_zeros` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestEcbPatternLeakage::test_ecb_pattern_leakage` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestSensitivePreservation::test_sensitive_preserved_on_copy` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestSensitivePreservation::test_extractable_cannot_escalate_on_copy` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestPrivateAttribute::test_non_private_object_visible_without_login` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **[1]** `TestAESGCMCrossVerify::test_gcm_256_encrypt_crossverify` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_GENERAL_ERROR; expected one of: CKR_OK
- **[1]** `TestAESGCMCrossVerify::test_gcm_128_encrypt_crossverify` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_GENERAL_ERROR; expected one of: CKR_OK
- **[1]** `TestAESGCMCrossVerify::test_gcm_decrypt_crossverify` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_GENERAL_ERROR; expected one of: CKR_OK
- **[1]** `TestAESGCMProperties::test_gcm_different_nonces_different_ct` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestAESGCMProperties::test_gcm_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestDuplicateAttributes::test_create_key_normal` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestConcurrentSessions::test_two_sessions_see_same_token_object` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestConcurrentSessions::test_destroy_in_one_session_reflected_in_other` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestConcurrentSessions::test_use_key_from_concurrent_session` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestConcurrentObjectCreation::test_rapid_create_destroy_cycle` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestConcurrentObjectCreation::test_create_in_both_sessions_no_conflict` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestDuplicateLabels::test_two_keys_same_label` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestDuplicateLabels::test_different_types_same_label` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestDuplicateLabels::test_destroy_one_of_duplicates` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED; expected one of: CKR_OK
- **[1]** `TestECDSACrossVerify::test_ecdsa_sign_p11_verify_crypto` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_GENERAL_ERROR; expected one of: CKR_OK
- **[1]** `TestECDSACrossVerify::test_ecdsa_sign_p11_verify_crypto` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_HOST_MEMORY; expected one of: CKR_OK
- **[1]** `TestECPublicKeyImport::test_generate_export_import_verify` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_HOST_MEMORY; expected one of: CKR_OK
- **[1]** `TestRSAEncryption::test_rsa_pkcs_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **[1]** `TestRSAEncryption::test_rsa_oaep_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- … +30 more classes (see failure-inventory.json)

## Other (125)

- **[43]** `test_rsa_pss` — Valid RSA-PSS sig VEC rejected by module
- **[39]** `test_rsa_pss` — Invalid RSA-PSS sig VEC accepted by module
- **[27]** `TestRsaSigVer::test_rsa_pkcs15_verify` — SigVer-pkcsN-ver-SHA-N-tc: rejected VALID signature
- **[1]** `TestGenerateKeyErrors::test_bad_key_size_zero` — C_GenerateKey(invalid_key_size): got CKR_FUNCTION_NOT_SUPPORTED, not in acceptable set ['CKR_ATTRIBUTE_VALUE_I
- **[1]** `TestGenerateKeyErrors::test_bad_key_size_non_standard` — C_GenerateKey(invalid_key_size): got CKR_FUNCTION_NOT_SUPPORTED, not in acceptable set ['CKR_ATTRIBUTE_VALUE_I
- **[1]** `TestGenerateKeyErrors::test_template_inconsistent` — C_GenerateKey(conflicting_attributes): got CKR_FUNCTION_NOT_SUPPORTED, not in acceptable set ['CKR_ATTRIBUTE_T
- **[1]** `TestGenerateKeyPairErrors::test_attribute_type_invalid` — C_GenerateKey(bogus_attribute_in_template): got CKR_FUNCTION_NOT_SUPPORTED, not in acceptable set ['CKR_ATTRIB
- **[1]** `TestSignInitErrors::test_mechanism_invalid` — Should have rejected AES_ECB as signing mechanism
- **[1]** `TestVerifyInitErrors::test_mechanism_invalid` — Should have rejected AES_ECB as verify mechanism
- **[1]** `TestLoginStates::test_public_session_no_private_keys` — assert N == N
- **[1]** `TestECKeyLifecycle::test_ec_export_import_verify` — C_GenerateKeyPair failed: CKR_ATTRIBUTE_VALUE_INVALID
- **[1]** `TestSessionObjectLifecycle::test_session_data_object_gone_after_close` — Session data object survived session close
- **[1]** `TestSessionObjectCrossVisibility::test_session_object_gone_when_creating_session_closes` — Session object survived owning session close
- **[1]** `TestROSessionOperations::test_verify_in_ro_session` — assert False is True
- **[1]** `TestStaleSessionHandles::test_generate_key_after_close` — Expected CKR_SESSION_HANDLE_INVALID or CKR_SESSION_CLOSED, got CKR_FUNCTION_NOT_SUPPORTED
- **[1]** `TestLoginStateTransitions::test_open_session_is_public` — Private keys visible without login - not public state
- **[1]** `TestRSASignature::test_rsa_hash_mechanisms` — assert False is True
- **[1]** `TestForkSafety::test_fork_after_initialize` — subprocess.TimeoutExpired: Command '['/app/.venv/bin/python', '-c', '\nimport os\nfrom pkcsN_check.raw.api imp
- **[1]** `TestCertificateLifecycle::test_cert_modifiability` — Successfully modified label on non-modifiable cert
