# Findings: `kryoptic`

Failures **115** · file-crashes **0** · classes **38** (sum 115). Root causes: [catalog.md](catalog.md); raw: [failure-inventory.json](failure-inventory.json).

## Crash (signal) (22)

- **[3]** `TestTemplateCountOverflow::test_template_count_overflow` — C_FindObjectsInit(template_count=H): module crashed with signal N
- **[3]** `TestTemplateCountOverflow::test_template_count_overflow` — C_UnwrapKey(template_count=H): module crashed with signal N
- **[2]** `TestIsizeMaxDataLength::test_sign_isize_boundary` — C_Sign(HMAC_SHAN, ulDataLen=H): module crashed with signal N
- **[2]** `TestIsizeMaxDataLength::test_digest_isize_boundary` — C_Digest(SHAN, ulDataLen=H): module crashed with signal N
- **[1]** `TestNullRandomBuffer::test_generate_random_null_buffer` — C_GenerateRandom(buf=NULL, buf_len=N): module crashed with signal N
- **[1]** `TestNullOperationState::test_set_operation_state_null_buffer` — C_SetOperationState(state=NULL, state_len=N): module crashed with signal N
- **[1]** `TestNullParameters::test_get_info_null` — C_GetInfo(NULL): subprocess crashed with signal N; module does not validate NULL parameters
- **[1]** `TestArgsBadNullPointers::test_generate_key_null_mechanism` — C_GenerateKey(NULL mech): module crashed with signal N
- **[1]** `TestNullTemplateNonzeroCount::test_null_template_nonzero_count` — C_CreateObject(template=NULL, count=N): module crashed with signal N
- **[1]** `TestNullTemplateNonzeroCount::test_null_template_nonzero_count` — C_FindObjectsInit(template=NULL, count=N): module crashed with signal N
- **[1]** `TestNullTemplateNonzeroCount::test_null_template_nonzero_count` — C_GenerateKey(template=NULL, count=N): module crashed with signal N
- **[1]** `TestGenerateAesExtremeKeySize::test_generate_aes_extreme_key_size` — C_GenerateKey(CKA_VALUE_LEN=H): module crashed with signal N
- **[1]** `TestKeyValueLenOverflow::test_key_value_len_overflow` — C_GenerateKey(CKM_AES_KEY_GEN, CKA_VALUE_LEN=H): module crashed with signal N
- **[1]** `TestTlsKdfNullParams::test_tls_kdf_null_label` — C_DeriveKey(TLS_KDF, pLabel=NULL, ulLabelLength=N): module crashed with signal N
- **[1]** `TestSp800108NullDataParams::test_sp800_108_null_data_params` — C_DeriveKey(SPN_N_COUNTER_KDF, pDataParams=NULL, ulNumberOfDataParams=N): module crashed with signal N
- **[1]** `TestHmacGeneralNullParam::test_hmac_general_null_parameter` — C_SignInit(CKM_SHAN_HMAC_GENERAL, pParameter=NULL, ulParameterLen=N): module crashed with signal N

## Abort (exit code) (3)

- **[1]** `TestGcmAadNullWithLength::test_gcm_null_aad_pointer_nonzero_length` — GCM NULL AAD pointer with nonzero ulAADLen: subprocess failed with exit code N
- **[1]** `TestEncapsulateKeyErrors::test_encapsulate_null_pointers` — C_EncapsulateKey_NULLs: subprocess failed with exit code N; stdout: NULL pMechanism -> CKR:H; stderr: Tracebac
- **[1]** `TestDecapsulateKeyErrors::test_decapsulate_null_pointers` — C_DecapsulateKey_NULLs: subprocess failed with exit code N; stdout: NULL pMechanism -> CKR:H; stderr: Tracebac

## Accept-invalid (crypto) (66)

- **[62]** `test_rsa_pkcs1_decrypt` — RSA PKCS#N decrypt VEC accepted invalid ciphertext
- **[4]** `TestEdDsaKeyVer::test_eddsa_keyver` — EDDSA-KeyVer-ED-N-tc: Module ACCEPTED an INVALID EdDSA key

## Wrong CK_RV (8)

- **[6]** `test_mldsa_sign` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK
- **[1]** `TestAESCTS::test_aes_cts_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK
- **[1]** `TestAESCTS::test_aes_cts_different_keys` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK

## Other (16)

- **[3]** `test_mldsa_sign` — Invalid ML-DSA sign vector VEC accepted by module
- **[1]** `TestTookanUnwrapAttrs::test_unwrapped_key_cannot_unset_sensitive` — SECURITY: Tookan §N.N — unwrap with CKA_SENSITIVE=False produced a non-sensitive copy of a SENSITIVE=True key.
- **[1]** `TestAESPaddingOracle::test_cbc_pad_all_last_block_positions` — SECURITY: AES-CBC-PAD padding oracle (Vaudenay N) — distinct outcomes {'CKR_ENCRYPTED_DATA_INVALID': N, 'CKR_O
- **[1]** `TestTrustedAttribute::test_user_cannot_set_trusted` — SECURITY: USER session created and was granted CKA_TRUSTED=True on a freshly-generated key — trust boundary br
- **[1]** `TestOutputBufferEdgeCases::test_sign_final_buffer_too_small_then_correct` — After CKR_BUFFER_TOO_SMALL, pulSize must be N (RSA-N); got N
- **[1]** `TestMessageEncrypt::test_message_encrypt_aes_gcm_generated_iv_writeback` — C_EncryptMessage did not write generated IV to pIv
- **[1]** `TestWrapKeyErrors::test_wrapping_key_type_inconsistent` — Module accepted a generic-secret key for AES wrap (expected CKR_WRAPPING_KEY_TYPE_INCONSISTENT)
- **[1]** `TestAllocationGuard::test_generate_key_oom_value_len` — subprocess.TimeoutExpired: Command '['/app/.venv/bin/python', '-c', 'from pkcsN_check.raw.api import RawPKCSN\
- **[1]** `TestMessageEncrypt::test_message_encrypt_aes_ccm_generated_nonce_writeback` — C_EncryptMessage did not write generated nonce
- **[1]** `TestExtractKeyFromKey::test_extract_from_offset_zero` — Expected H, got H
- **[1]** `TestExtractKeyFromKey::test_extract_at_byte_boundary_offset` — Expected H, got H
- **[1]** `TestSessionCancel::test_cancel_after_digest_init_subprocess` — Module crashed (signal N) during C_DigestInit/C_SessionCancel - C_SessionCancel not safely callable. Stderr:
- **[1]** `TestOutputBufferEdgeCases::test_digest_final_buffer_too_small_then_correct` — After CKR_BUFFER_TOO_SMALL, pulSize must equal required size; got N, expected N
- **[1]** `TestOutputBufferEdgeCases::test_digest_final_preserves_state_across_multiple_retries` — Retry #N: pulSize must be N, got N
