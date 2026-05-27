# Findings: `nss-pqc`

Failures **119** · file-crashes **2** · classes **52** (sum 119). Root causes: [catalog.md](catalog.md); raw: [failure-inventory.json](failure-inventory.json).

## File-level crashes

- `src/pkcs11_check/testcases/test_mech_flags.py` — rc=11 (SIGSEGV)
- `src/pkcs11_check/testcases/test_mech_negative.py` — rc=11 (SIGSEGV)

## Crash (signal) (18)

- **[2]** `TestIsizeMaxDataLength::test_sign_isize_boundary` — C_Sign(HMAC_SHAN, ulDataLen=H): module crashed with signal N
- **[1]** `TestNullRandomBuffer::test_generate_random_null_buffer` — C_GenerateRandom(buf=NULL, buf_len=N): module crashed with signal N
- **[1]** `TestNullOperationState::test_set_operation_state_null_buffer` — C_SetOperationState(state=NULL, state_len=N): module crashed with signal N
- **[1]** `TestMechanismNullInnerParams::test_gcm_null_iv` — C_EncryptInit(AES_GCM, pIv=NULL, ulIvLen=N): module crashed with signal N
- **[1]** `TestNullParameters::test_get_info_null` — C_GetInfo(NULL): subprocess crashed with signal N; module does not validate NULL parameters
- **[1]** `TestArgsBadNullPointers::test_generate_key_null_mechanism` — C_GenerateKey(NULL mech): module crashed with signal N
- **[1]** `TestNullTemplateNonzeroCount::test_null_template_nonzero_count` — C_CreateObject(template=NULL, count=N): module crashed with signal N
- **[1]** `TestNullTemplateNonzeroCount::test_null_template_nonzero_count` — C_FindObjectsInit(template=NULL, count=N): module crashed with signal N
- **[1]** `TestNullTemplateNonzeroCount::test_null_template_nonzero_count` — C_GenerateKey(template=NULL, count=N): module crashed with signal N
- **[1]** `TestNullRandomBuffer::test_seed_random_null_buffer` — C_SeedRandom(data=NULL, data_len=N): module crashed with signal N
- **[1]** `TestArgsBadNullPointers::test_digest_init_null_mechanism` — C_DigestInit(NULL mech): module crashed with signal N
- **[1]** `TestNullMechanismInit::test_null_mechanism_init` — C_DigestInit(mechanism=NULL): module crashed with signal N
- **[1]** `TestNullParameters::test_get_slot_list_null_count` — C_GetSlotList(NULL): subprocess crashed with signal N; module does not validate NULL parameters
- **[1]** `TestNullDataUpdate::test_null_data_update` — C_SignUpdate(data=NULL, data_len=N): module crashed with signal N
- **[1]** `TestNullDataUpdate::test_null_data_update` — C_VerifyUpdate(data=NULL, data_len=N): module crashed with signal N
- **[1]** `TestNullDataOneShot::test_null_data_oneshot` — C_Sign(data=NULL, data_len=N): module crashed with signal N
- **[1]** `TestNullDataOneShot::test_null_data_oneshot` — C_Verify(data=NULL, data_len=N): module crashed with signal N

## Abort (exit code) (22)

- **[5]** `TestBitFlipUnwrap::test_bit_flip_unwrap` — CKM_AES_KEY_WRAP_KWP unwrap: bit_flip at byte N: subprocess failed with exit code N
- **[1]** `TestGcmAadNullWithLength::test_gcm_null_aad_pointer_nonzero_length` — GCM NULL AAD pointer with nonzero ulAADLen: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=aiv: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=padding: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=length: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=truncate: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=extend: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=random: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=all_zeros: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP decrypt: corruption=all_ff: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP unwrap: corruption=aiv: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP unwrap: corruption=padding: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP unwrap: corruption=length: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP unwrap: corruption=truncate: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP unwrap: corruption=extend: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP unwrap: corruption=random: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP unwrap: corruption=all_zeros: subprocess failed with exit code N
- **[1]** `TestCorruptedUnwrap::test_corrupted_unwrap` — CKM_AES_KEY_WRAP_KWP unwrap: corruption=all_ff: subprocess failed with exit code N

## Accept-invalid (crypto) (64)

- **[62]** `test_rsa_pkcs1_decrypt` — RSA PKCS#N decrypt VEC accepted invalid ciphertext
- **[2]** `TestEdDsaKeyVer::test_eddsa_keyver` — EDDSA-KeyVer-ED-N-tc: Module ACCEPTED an INVALID EdDSA key

## Wrong CK_RV (1)

- **[1]** `test_mlkem_decaps` — Module does not support ML-KEM 'semi_expanded' (seed-format) private key import: Unexpected CK_RV CKR_ATTRIBUT

## Other (14)

- **[1]** `TestTookanUnwrapAttrs::test_unwrapped_key_cannot_unset_sensitive` — SECURITY: Tookan §N.N — unwrap with CKA_SENSITIVE=False produced a non-sensitive copy of a SENSITIVE=True key.
- **[1]** `TestAESPaddingOracle::test_cbc_pad_all_last_block_positions` — SECURITY: AES-CBC-PAD padding oracle (Vaudenay N) — distinct outcomes {'CKR_ENCRYPTED_DATA_INVALID': N, 'CKR_O
- **[1]** `TestTrustedAttribute::test_user_cannot_set_trusted` — SECURITY: USER session created and was granted CKA_TRUSTED=True on a freshly-generated key — trust boundary br
- **[1]** `TestOutputBufferEdgeCases::test_sign_final_buffer_too_small_then_correct` — After CKR_BUFFER_TOO_SMALL, pulSize must be N (RSA-N); got N
- **[1]** `TestMessageEncrypt::test_message_encrypt_aes_gcm_generated_iv_writeback` — C_EncryptMessage did not write generated IV to pIv
- **[1]** `test_cts_variant_detected` — Module advertises CKM_AES_CTS but CTS variant detection failed. The module errors on CTS encrypt probes -- CTS
- **[1]** `TestInitializeErrors::test_finalize_not_initialized` — C_Finalize after C_Finalize: child subprocess did not emit an OK marker; stdout: CKR:finalize_accepted
- **[1]** `TestWrapKeyErrors::test_key_not_extractable` — SECURITY: module returns CKR_OK for C_WrapKey on CKA_EXTRACTABLE=False key (expected CKR_KEY_UNEXTRACTABLE) — 
- **[1]** `TestCopyObject::test_non_copyable_key_rejected` — SECURITY: module copied a CKA_COPYABLE=False key — copy-prohibition silently ignored
- **[1]** `TestDestroyable::test_destroyable_false_blocks_destroy` — SECURITY: C_DestroyObject succeeded on CKA_DESTROYABLE=False key — DESTROYABLE access control silently ignored
- **[1]** `TestMechEncryptKAT::test_kat_vector` — KAT ciphertext mismatch for chachaN_polyN_N_with_aad: got 'H', expected 'H'
- **[1]** `TestMechWrapRoundtrip::test_wrap_unwrap_aes_key` — RSA_X_N: decrypt mismatch after unwrap -- expected 'H', got 'H' Raw RSA unwrap hint: the module appears to der
- **[1]** `test_limbo_attribute_parity` — TC crl::revoked-certificate-with-crl - Unexpected exception: <CKA_START_DATE: H>
- **[1]** `TestRSAPaddingOracle::test_oaep_error_uniformity` — SECURITY: RSA-OAEP padding oracle — non-uniform error codes: {'CKR_ARGUMENTS_BAD', 'CKR_ENCRYPTED_DATA_INVALID
