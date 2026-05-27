# Findings: `opencryptoki-master`

Failures **271** · file-crashes **0** · classes **51** (sum 271). Root causes: [catalog.md](catalog.md); raw: [failure-inventory.json](failure-inventory.json).

## Crash (signal) (8)

- **[3]** `TestTemplateCountOverflow::test_template_count_overflow` — C_FindObjectsInit(template_count=H): module crashed with signal N
- **[2]** `TestIsizeMaxDataLength::test_sign_isize_boundary` — C_Sign(HMAC_SHAN, ulDataLen=H): module crashed with signal N
- **[2]** `TestIsizeMaxDataLength::test_digest_isize_boundary` — C_Digest(SHAN, ulDataLen=H): module crashed with signal N
- **[1]** `TestMlDsaExplicitEmptyContext::test_mldsa_verify_empty_context_nonnull_pointer` — C_Verify(ML-DSA, pContext non-NULL, ulContextLen=N): module crashed with signal N

## Abort (exit code) (9)

- **[1]** `TestGcmAadNullWithLength::test_gcm_null_aad_pointer_nonzero_length` — GCM NULL AAD pointer with nonzero ulAADLen: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=aiv: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=padding: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=length: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=truncate: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=extend: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=random: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=all_zeros: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=all_ff: subprocess failed with exit code N

## Accept-invalid (crypto) (63)

- **[59]** `test_rsa_pkcs1_decrypt` — RSA PKCS#N decrypt VEC accepted invalid ciphertext
- **[4]** `TestEdDsaKeyVer::test_eddsa_keyver` — EDDSA-KeyVer-ED-N-tc: Module ACCEPTED an INVALID EdDSA key

## Wrong CK_RV (23)

- **[3]** `test_mlkem_decaps` — Module does not support ML-KEM 'semi_expanded' key format decapsulation: Unexpected CK_RV CKR_TEMPLATE_INCONSI
- **[1]** `TestROWrapUnwrapRestrictions::test_unwrap_to_token_object_in_ro_fails` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_TEMPLATE_INCOMPLETE; expected one of: CKR_OK
- **[1]** `TestAESGCMProviderGeneratedIV::test_gcm_generated_iv_strict_writeback_two_call` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **[1]** `TestAESCTR::test_aes_ctr_different_keys` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DATA_LEN_RANGE; expected one of: CKR_OK
- **[1]** `TestAESCTR::test_aes_ctr_non_block_aligned` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DATA_LEN_RANGE; expected one of: CKR_OK
- **[1]** `TestAESCTS::test_aes_cts_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestAESCTS::test_aes_cts_different_keys` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_MECHANISM_INVALID; expected one of: CKR_OK
- **[1]** `TestAESKeyWrapPKCS7::test_aes_key_wrap_pkcs7_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_TEMPLATE_INCOMPLETE; expected one of: CKR_OK
- **[1]** `test_eddsa_public_key_encoding_support` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_OK
- **[1]** `TestAESKeyWrapKWP::test_wrap_unwrap_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY; expected one of: CKR_OK
- **[1]** `TestAESKeyWrapKWP::test_wrap_unwrap_256bit_key` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY; expected one of: CKR_OK
- **[1]** `TestAESKeyWrapLifecycle::test_aes_wrap_unwrap_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY; expected one of: CKR_OK
- **[1]** `TestAESKeyWrapLifecycle::test_aes_wrapped_key_functional` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY; expected one of: CKR_OK
- **[1]** `TestKeyWrapUnwrap::test_wrap_unwrap_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY; expected one of: CKR_OK
- **[1]** `TestRoundTripInvariants::test_wrap_unwrap_preserves_material` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY; expected one of: CKR_OK
- **[1]** `TestRSAAESKeyWrap::test_wrap_unwrap_aes128` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY; expected one of: CKR_OK
- **[1]** `TestRSAAESKeyWrap::test_wrap_unwrap_aes256` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY; expected one of: CKR_OK
- **[1]** `TestRSAPKCSWrap::test_wrap_unwrap_aes128` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY; expected one of: CKR_OK
- **[1]** `TestRSAPKCSWrap::test_wrap_unwrap_aes256` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY; expected one of: CKR_OK
- **[1]** `TestRSAOAEPWrap::test_wrap_unwrap_oaep` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY; expected one of: CKR_OK
- **[1]** `TestWrappedKeyUsability::test_unwrapped_key_encrypts` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY; expected one of: CKR_OK

## Other (168)

- **[144]** `TestAESCBCPKCS5Wycheproof::test_aes_cbc_pkcs5` — Invalid AES-CBC vector tc decrypted successfully
- **[9]** `TestMlDsaSigVer::test_acvp_mldsa_sigver` — ML-DSA-sigVer-ML-DSA-N-tc: module rejected a VALID ML-DSA signature
- **[3]** `test_mldsa_sign` — Invalid ML-DSA sign vector VEC accepted by module
- **[1]** `TestHandleReuseAfterDestroy::test_wrap_after_destroy` — Expected destroyed-handle CKR for C_WrapKey, got CKR_WRAPPING_KEY_HANDLE_INVALID
- **[1]** `TestSensitiveExtraction::test_private_key_not_extractable` — SECURITY: CKA_PRIVATE_EXPONENT readable -- private key material exposed
- **[1]** `TestECDSATimingBasic::test_ecdsa_timing_variance` — ECDSA timing CV=N.N (mean=N.Nms, stdev=N.Nms) - possible timing leak
- **[1]** `TestTookanUnwrapAttrs::test_unwrapped_key_preserves_extractable` — Tookan: unwrapped key is EXTRACTABLE despite template saying False
- **[1]** `TestAESPaddingOracle::test_cbc_pad_all_last_block_positions` — SECURITY: AES-CBC-PAD padding oracle (Vaudenay N) — distinct outcomes {'CKR_OK_DIFFERENT': N, 'CKR_OK_MATCH': 
- **[1]** `TestAESCTR::test_aes_ctr_counter_bits_zero_rejected` — C_EncryptInit accepted ulCounterBits=N (rv=H), spec requires rejection
- **[1]** `TestAESCTR::test_aes_ctr_counter_bits_129_rejected` — C_EncryptInit accepted ulCounterBits=N (rv=H), spec requires rejection
- **[1]** `TestCheckValue::test_generated_key_has_check_value` — Expected N-byte KCV, got N bytes
- **[1]** `TestCheckValue::test_imported_key_kcv_matches_ecb_encrypt` — KCV mismatch: got , expected NeNb
- **[1]** `TestOutputBufferEdgeCases::test_sign_final_buffer_too_small_then_correct` — Retry C_SignFinal with N-byte buffer returned H — signature state was not preserved across BUFFER_TOO_SMALL
- **[1]** `TestVerifySignatureRoundtrip::test_verify_signature_multipart` — C_VerifySignatureUpdate failed with H
- **[1]** `TestRSAPaddingOracle::test_oaep_error_uniformity` — SECURITY: RSA-OAEP padding oracle — non-uniform error codes: {'CKR_ENCRYPTED_DATA_INVALID', 'CKR_FUNCTION_FAIL
