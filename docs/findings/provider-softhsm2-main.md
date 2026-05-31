# Findings: `softhsm2-main`

Failures **97** · file-crashes **0** · classes **19** (sum 97). Root causes: [catalog.md](catalog.md); raw: [failure-inventory.json](failure-inventory.json).

## Crash (signal) (9)

- **[3]** `TestTemplateCountOverflow::test_template_count_overflow` — C_CreateObject(template_count=H): module crashed with signal N
- **[3]** `TestTemplateCountOverflow::test_template_count_overflow` — C_GenerateKey(template_count=H): module crashed with signal N
- **[2]** `TestGenerateKeyPairCountOverflow::test_generate_key_pair_count_overflow` — C_GenerateKeyPair(pub_count=H, priv_count=H): module crashed with signal N
- **[1]** `TestMechanismNullInnerParams::test_gcm_null_iv` — C_EncryptInit(AES_GCM, pIv=NULL, ulIvLen=N): module crashed with signal N

## Abort (exit code) (6)

- **[2]** `TestIsizeMaxDataLength::test_sign_isize_boundary` — C_Sign(HMAC_SHAN, ulDataLen=H): subprocess failed with exit code N
- **[2]** `TestIsizeMaxDataLength::test_digest_isize_boundary` — C_Digest(SHAN, ulDataLen=H): subprocess failed with exit code N
- **[1]** `TestGcmAadNullWithLength::test_gcm_null_aad_pointer_nonzero_length` — GCM NULL AAD pointer with nonzero ulAADLen: subprocess failed with exit code N
- **[1]** `TestMechanismParamLengthOverflow::test_mechanism_param_length_overflow` — C_EncryptInit(CKM_AES_CBC, pParameter=NB, ulParameterLen=H): subprocess failed with exit code N

## Accept-invalid (crypto) (63)

- **[59]** `test_rsa_pkcs1_decrypt` — RSA PKCS#N decrypt VEC accepted invalid ciphertext
- **[4]** `TestEdDsaKeyVer::test_eddsa_keyver` — EDDSA-KeyVer-ED-N-tc: Module ACCEPTED an INVALID EdDSA key

## Wrong CK_RV (3)

- **[1]** `TestROWrapUnwrapRestrictions::test_unwrap_to_token_object_in_ro_fails` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_TEMPLATE_INCOMPLETE; expected one of: CKR_OK
- **[1]** `TestWrapIntegrity::test_aes_key_wrap_bit_flip_detected` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_GENERAL_ERROR; expected one of: CKR_OK
- **[1]** `TestRSAOAEPWrapLifecycle::test_rsa_oaep_wrap_aes_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_ARGUMENTS_BAD; expected one of: CKR_OK

## Other (16)

- **[9]** `TestMlDsaSigVer::test_acvp_mldsa_sigver` — ML-DSA-sigVer-ML-DSA-N-tc: module rejected a VALID ML-DSA signature
- **[3]** `test_mldsa_sign` — Invalid ML-DSA sign vector VEC accepted by module
- **[1]** `TestTookanUnwrapAttrs::test_unwrapped_key_cannot_unset_sensitive` — SECURITY: Tookan §N.N — unwrap with CKA_SENSITIVE=False produced a non-sensitive copy of a SENSITIVE=True key.
- **[1]** `TestAESPaddingOracle::test_cbc_pad_all_last_block_positions` — SECURITY: AES-CBC-PAD padding oracle (Vaudenay N) — distinct outcomes {'CKR_ENCRYPTED_DATA_INVALID': N, 'CKR_O
- **[1]** `TestHandleReuseAfterDestroy::test_wrap_after_destroy` — Expected destroyed-handle CKR for C_WrapKey, got CKR_WRAPPING_KEY_HANDLE_INVALID
- **[1]** `TestKeyTypeConfusionOnUnwrap::test_unwrap_aes_as_des3_rejected` — SECURITY: Tookan §N.N — module unwrapped an AES-wrapped blob as CKK_DESN (key-type confusion). Attacker can ru
