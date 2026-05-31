# Findings: `pkcs11-mock`

Failures **1353** · file-crashes **0** · classes **490** (sum 1353). Root causes: [catalog.md](catalog.md); raw: [failure-inventory.json](failure-inventory.json).

## Abort (exit code) (1)

- **[1]** `TestOperationStateSubprocess::test_double_digest_init_via_subprocess` — double C_DigestInit: subprocess failed with exit code N

## Accept-invalid (crypto) (1)

- **[1]** `TestMalformedAttributes::test_invalid_class_value` — Module accepted invalid CKA_CLASS value H

## Wrong CK_RV (79)

- **[1]** `TestDataObjectCreate::test_create_data_object_empty_value` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID; expected one of: CKR_OK
- **[1]** `TestCKRPinErrors::test_ckr_pin_incorrect` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_SESSION_COUNT; expected one of: CKR_OK
- **[1]** `TestCKRMechanismErrors::test_ckr_mechanism_invalid` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestCKRDataErrors::test_ckr_data_len_range_ecb` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestCKRAttributeErrors::test_ckr_attribute_sensitive` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestCKRAttributeErrors::test_ckr_attribute_type_invalid` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestCKRObjectErrors::test_ckr_object_handle_invalid_after_destroy` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestDeriveKeyErrors::test_mechanism_invalid` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestOperationStateWrapper::test_digest_twice_succeeds` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestGetAttributeErrors::test_sensitive_value` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestGetAttributeErrors::test_destroyed_handle` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestCopyObjectErrors::test_copy_destroyed_handle` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestDestroyObjectErrors::test_destroy_already_destroyed` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestErrorPriority::test_destroyed_handle_with_wrong_mechanism` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestErrorPriority::test_bad_mechanism_with_bad_key_size` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestLoginErrors::test_wrong_pin` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_SESSION_COUNT; expected one of: CKR_OK
- **[1]** `TestLogoutErrors::test_logout_when_not_logged_in` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_SESSION_COUNT; expected one of: CKR_OK
- **[1]** `TestSignInitErrors::test_key_type_inconsistent` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestCKRMechanismCompliance::test_sha256_as_encrypt_returns_mechanism_invalid` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestCKRMechanismCompliance::test_non_aligned_ecb_returns_data_len_range` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestCKRAttributeCompliance::test_sensitive_value_returns_attribute_sensitive` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestCKRObjectCompliance::test_destroyed_handle_returns_object_handle_invalid` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestCKRVerifyCompliance::test_bad_signature_returns_signature_invalid` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestCKRMultipartCompliance::test_aes_cbc_multipart_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestCKRMultipartCompliance::test_sha256_multipart_digest` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestVerifyInitErrors::test_key_type_inconsistent` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestVerifyErrors::test_signature_invalid` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestCbcIvAllZeros::test_cbc_iv_all_zeros` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestSensitivePreservation::test_sensitive_preserved_on_copy` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestSensitivePreservation::test_extractable_cannot_escalate_on_copy` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestAESGCMCrossVerify::test_gcm_256_encrypt_crossverify` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestAESGCMCrossVerify::test_gcm_128_encrypt_crossverify` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestAESGCMCrossVerify::test_gcm_decrypt_crossverify` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestAESGCMProperties::test_gcm_different_nonces_different_ct` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestAESGCMProperties::test_gcm_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestDuplicateAttributes::test_create_key_normal` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestConcurrentSessions::test_two_sessions_see_same_token_object` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestConcurrentSessions::test_destroy_in_one_session_reflected_in_other` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestConcurrentObjectCreation::test_rapid_create_destroy_cycle` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestConcurrentObjectCreation::test_create_in_both_sessions_no_conflict` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestConcurrentDataObjects::test_data_object_visible_across_sessions` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_SESSION_COUNT; expected one of: CKR_OK
- **[1]** `TestAESCBCCrossVerify::test_aes_cbc_encrypt_crossverify` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_KEY_TYPE_INCONSISTENT; expected one of: CKR_OK
- **[1]** `TestAESCBCCrossVerify::test_aes_cbc_decrypt_crossverify` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_KEY_TYPE_INCONSISTENT; expected one of: CKR_OK
- **[1]** `TestDuplicateLabels::test_two_keys_same_label` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestDuplicateLabels::test_different_types_same_label` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestDuplicateLabels::test_destroy_one_of_duplicates` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestInterfaceV30::test_v30_encrypt_decrypt_aes` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestKeyDeriveSoftware::test_hmac_as_kdf` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestKeyDeriveSoftware::test_hmac_sha512_as_kdf` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestRSAKeyLifecycle::test_rsa_export_import_verify` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- … +29 more classes (see failure-inventory.json)

## Other (1272)

- **[529]** `test_exhaustive_cert_import_no_crash` — bettertls::nameconstraints::tc: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[30]** `test_import_limbo_failure_cert_raw` — bettertls::nameconstraints::tc: module stored modified cert bytes - CKA_VALUE mismatch (NB stored vs NB sent)
- **[14]** `test_exhaustive_cert_import_no_crash` — cve::cve-N-N: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[9]** `test_exhaustive_cert_import_no_crash` — pathlen::ee-with-intermediate-pathlen-N: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[7]** `test_exhaustive_cert_import_no_crash` — pathlen::max-chain-depth-N-exhausted: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[6]** `test_exhaustive_cert_import_no_crash` — pathological::nc-dos-N: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[6]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::nc-forbids-same-chain-ica: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[5]** `test_exhaustive_cert_import_no_crash` — pathlen::intermediate-pathlen-too-long: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[5]** `test_exhaustive_cert_import_no_crash` — pathlen::self-issued-certs-pathlen: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[5]** `test_exhaustive_cert_import_no_crash` — pathlen::max-chain-depth-N: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[5]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::nc-forbids-alternate-chain-ica: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[4]** `test_exhaustive_cert_import_no_crash` — pathlen::intermediate-violates-pathlen-N: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[4]** `test_exhaustive_cert_import_no_crash` — pathlen::intermediate-pathlen-may-increase: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[4]** `test_exhaustive_cert_import_no_crash` — pathlen::max-chain-depth-N-self-issued: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[4]** `test_exhaustive_cert_import_no_crash` — pathological::multiple-chains-expired-intermediate: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[4]** `test_exhaustive_cert_import_no_crash` — pathological::intermediate-cycle-distinct-cas: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[4]** `test_exhaustive_cert_import_no_crash` — pathological::intermediate-cycle-distinct-cas-max-depth: CKA_VALUE round-trip mismatch (stored NB vs original 
- **[4]** `test_exhaustive_cert_import_no_crash` — pathological::intermediate-cycle-same-logical-ca: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[4]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::excluded-ipvN-match: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[4]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::permitted-ipvN-match: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[4]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::invalid-ipvN-address: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[4]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::intermediate-with-san-rejected-by-intermediate-nc: CKA_VALUE round-trip mismatch (stored NB vs origi
- **[4]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::intermediate-with-san-rejected-by-root-nc: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[4]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::restrictive-permits-in-intermediates-narrows: CKA_VALUE round-trip mismatch (stored NB vs original N
- **[4]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::restrictive-permits-in-intermediates-widens: CKA_VALUE round-trip mismatch (stored NB vs original NB
- **[4]** `test_exhaustive_cert_import_no_crash` — rfcN::unknown-critical-extension-unrelated-intermediate: CKA_VALUE round-trip mismatch (stored NB vs original 
- **[4]** `test_exhaustive_cert_import_no_crash` — rfcN::chain-untrusted-root: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[3]** `TestRsaKeyGen::test_rsa_keygen_attributes` — FIPSN-N-N-tc: Public exponent must be odd
- **[3]** `TestAESKeySizes::test_aes_import_export` — assert b'Hello world!' == b'\xN\xN\xN...N\xN\xN\xN'
- **[3]** `TestRSAKeySizes::test_rsa_generate` — assert N == (N // N)
- **[3]** `test_import_limbo_failure_cert_raw` — pathological::nc-dos-N: module stored modified cert bytes - CKA_VALUE mismatch (NB stored vs NB sent)
- **[3]** `test_exhaustive_cert_import_no_crash` — crl::certificate-serial-on-crl-different-issuer: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[3]** `test_exhaustive_cert_import_no_crash` — cve::cve-N-N-nc-permits-variant: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[3]** `test_exhaustive_cert_import_no_crash` — invalid::invalid-issuer-key: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[3]** `test_exhaustive_cert_import_no_crash` — pathlen::validation-ignores-pathlen-in-leaf: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[3]** `test_exhaustive_cert_import_no_crash` — rfcN::aki::intermediate-missing-aki: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[3]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::excluded-dns-match: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[3]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::permitted-self-issued: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[3]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::excluded-self-issued-leaf: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[3]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::nc-permits-invalid-dns-san: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[3]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::nc-permits-invalid-ip-san: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[3]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::nc-permits-invalid-email-san: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[3]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::nc-permits-email-exact: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[3]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::nc-permits-email-domain: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[3]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::nc-permits-email-literal-asterisk-exact-match: CKA_VALUE round-trip mismatch (stored NB vs original 
- **[3]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::nc-permits-email-literal-asterisk-rejects-user: CKA_VALUE round-trip mismatch (stored NB vs original
- **[3]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::nc-permits-email-literal-asterisk-rejects-subdomain: CKA_VALUE round-trip mismatch (stored NB vs ori
- **[3]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::nc-permits-email-literal-double-asterisk: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- **[3]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::nc-permits-email-literal-double-asterisk-rejects-single: CKA_VALUE round-trip mismatch (stored NB vs
- **[3]** `test_exhaustive_cert_import_no_crash` — rfcN::nc::nc-permits-email-literal-mid-asterisk: CKA_VALUE round-trip mismatch (stored NB vs original NB)
- … +359 more classes (see failure-inventory.json)
