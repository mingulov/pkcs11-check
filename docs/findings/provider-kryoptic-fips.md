# Findings: `kryoptic-fips`

Failures **70** · file-crashes **5** · classes **46** (sum 70). Root causes: [catalog.md](catalog.md); raw: [failure-inventory.json](failure-inventory.json).

## The crashes are a DEBUG-build artifact, not a FIPS-mode vulnerability

The SIGABRT (rc=6) "crashes" below are an artifact of how the FIPS variant is
**built**, not a kryoptic FIPS defect. `docker/kryoptic/Dockerfile.fips` builds
kryoptic with `cargo build` (**debug**, no `--release`) — kryoptic's reference CI
configuration. A Rust **debug** build enables integer-overflow checks and
`debug_assert!`, so the security/fuzz arguments (`ulDataLen=SIZE_MAX`,
`template_count=H`, `pNonce=NULL`, …) trigger a **panic → `abort()` (signal 6)**
*before* reaching the crypto. A release build compiles those checks out.

**Empirical support:** stable kryoptic **v1.5.0 (release)** runs the exact same
overflow/FFI tests (`test_parameter_validation`, `test_ffi_*`, the `*Overflow`
classes) with **0 crashes** (it returns `CKR_*` errors); the FIPS variant runs the
*same v1.5.0 source* in **debug** and aborts on them. The build mode is the only
relevant difference.

**Why FIPS can't simply be rebuilt in release (2026-05-29 investigation):**
`misc/hmacify.sh` needs a `.rodata1` section to hold the module HMAC. That section
is **not** in kryoptic's Rust source — it comes from the statically linked OpenSSL
(the simo5/openssl fork's Red Hat FIPS patches). A release build's section-GC
strips it (`objcopy: error: .rodata1 not found`); forcing it back with
`-Wl,--no-gc-sections` keeps `.rodata1` (hmacify then succeeds) but also retains
dead code referencing an unresolved symbol, so the module fails to load
(`undefined symbol: OSSL_PROVIDER_unload`). A clean release FIPS build therefore
needs upstream kryoptic build support (a linker-script `KEEP(.rodata1)` or
equivalent), not a Dockerfile/`RUSTFLAGS` tweak — which is why the reference CI
builds debug.

**Official OpenSSL is not (yet) usable for the FIPS build:** `--features fips,pqc`
*compiles* against official `openssl-4.0.0` (`enable-fips`), but the FIPS-integrity
packaging fails — official OpenSSL's FIPS is a separate `fips.so` provider and does
not emit the fork's `.rodata1`-embedded HMAC, so `hmacify` finds no `.rodata1`
(verified: official+debug and official+release both fail there; fork+debug is the
only working combination). The simo5/openssl fork stays required until kryoptic
adopts OpenSSL's upstream FIPS-indicator scheme (planned for OpenSSL 3.5+).

Distinct from stable kryoptic's historical crashes, which *were* OpenSSL-side
(release build + system OpenSSL 3.x → OOB in EVP) and went away with OpenSSL 4.0.0
— see [provider-kryoptic.md](provider-kryoptic.md) and module-issues.md.

## File-level crashes

- `src/pkcs11_check/testcases/acvp/aes/test_ccm.py` — rc=6 (SIGABRT)
- `src/pkcs11_check/testcases/test_mech_derive.py` — rc=6 (SIGABRT)
- `src/pkcs11_check/testcases/test_mech_encrypt.py` — rc=6 (SIGABRT)
- `src/pkcs11_check/testcases/test_misc_kdf.py` — rc=6 (SIGABRT)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py` — rc=6 (SIGABRT)

## Crash (signal) (31)

- **[3]** `TestTemplateCountOverflow::test_template_count_overflow` — C_FindObjectsInit(template_count=H): module crashed with signal N
- **[2]** `TestIsizeMaxDataLength::test_sign_isize_boundary` — C_Sign(HMAC_SHAN, ulDataLen=H): module crashed with signal N
- **[2]** `TestIsizeMaxDataLength::test_digest_isize_boundary` — C_Digest(SHAN, ulDataLen=H): module crashed with signal N
- **[2]** `TestTemplateCountOverflow::test_template_count_overflow` — C_CreateObject(template_count=H): module crashed with signal N
- **[2]** `TestTemplateCountOverflow::test_template_count_overflow` — C_GenerateKey(template_count=H): module crashed with signal N
- **[2]** `TestTemplateCountOverflow::test_template_count_overflow` — C_UnwrapKey(template_count=H): module crashed with signal N
- **[2]** `TestGenerateKeyPairCountOverflow::test_generate_key_pair_count_overflow` — C_GenerateKeyPair(pub_count=H, priv_count=H): module crashed with signal N
- **[2]** `TestDataLengthOverflow::test_data_length_overflow` — C_Encrypt(ulDataLen=H): module crashed with signal N
- **[2]** `TestDataLengthOverflow::test_data_length_overflow` — C_Decrypt(ulDataLen=H): module crashed with signal N
- **[1]** `TestNullRandomBuffer::test_generate_random_null_buffer` — C_GenerateRandom(buf=NULL, buf_len=N): module crashed with signal N
- **[1]** `TestNullOperationState::test_set_operation_state_null_buffer` — C_SetOperationState(state=NULL, state_len=N): module crashed with signal N
- **[1]** `TestNullRandomBuffer::test_seed_random_null_buffer` — C_SeedRandom(data=NULL, data_len=N): module crashed with signal N
- **[1]** `TestGenerateAesExtremeKeySize::test_generate_aes_extreme_key_size` — C_GenerateKey(CKA_VALUE_LEN=H): module crashed with signal N
- **[1]** `TestKeyValueLenOverflow::test_key_value_len_overflow` — C_GenerateKey(CKM_AES_KEY_GEN, CKA_VALUE_LEN=H): module crashed with signal N
- **[1]** `TestTlsKdfNullParams::test_tls_kdf_null_label` — C_DeriveKey(TLS_KDF, pLabel=NULL, ulLabelLength=N): module crashed with signal N
- **[1]** `TestSp800108NullDataParams::test_sp800_108_null_data_params` — C_DeriveKey(SPN_N_COUNTER_KDF, pDataParams=NULL, ulNumberOfDataParams=N): module crashed with signal N
- **[1]** `TestHmacGeneralNullParam::test_hmac_general_null_parameter` — C_SignInit(CKM_SHAN_HMAC_GENERAL, pParameter=NULL, ulParameterLen=N): module crashed with signal N
- **[1]** `TestLoginNullPin::test_login_null_pin_nonzero_length` — C_Login(pin=NULL, pin_len=N): module crashed with signal N
- **[1]** `TestIsizeMaxDataLength::test_encrypt_isize_boundary` — C_Encrypt(ulDataLen=H): module crashed with signal N
- **[1]** `TestIsizeMaxDataLength::test_decrypt_isize_boundary` — C_Decrypt(ulDataLen=H): module crashed with signal N
- **[1]** `TestAesCcmNullNonce::test_ccm_null_nonce` — C_EncryptInit(AES_CCM, pNonce=NULL, ulNonceLen=N): module crashed with signal N

## Abort (exit code) (1)

- **[1]** `TestGcmAadNullWithLength::test_gcm_null_aad_pointer_nonzero_length` — GCM NULL AAD pointer with nonzero ulAADLen: subprocess failed with exit code N

## Accept-invalid (crypto) (4)

- **[4]** `TestEdDsaKeyVer::test_eddsa_keyver` — EDDSA-KeyVer-ED-N-tc: Module ACCEPTED an INVALID EdDSA key

## Wrong CK_RV (22)

- **[6]** `test_mldsa_sign` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK
- **[5]** `test_rsa_wycheproof` — Valid RSA sig VEC rejected: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK
- **[1]** `TestAESCTS::test_aes_cts_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK
- **[1]** `TestAESCTS::test_aes_cts_different_keys` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK
- **[1]** `TestRSAKeySizeCrossVerify::test_rsa_2048_sha1` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK
- **[1]** `TestECDSAPrehash::test_sign_verify_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK
- **[1]** `TestECDSAPrehash::test_tampered_data_fails` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK
- **[1]** `TestECDSAPrehash::test_nondeterministic` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK
- **[1]** `TestRSAEncryption::test_rsa_pkcs_roundtrip` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK
- **[1]** `TestRSAInterop::test_rsa_multi_hash_interop` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK
- **[1]** `TestRSAPKCSWrap::test_wrap_unwrap_aes128` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK
- **[1]** `TestRSAPKCSWrap::test_wrap_unwrap_aes256` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK
- **[1]** `TestWrappedKeyUsability::test_unwrapped_key_encrypts` — pkcsN_check.raw.rv.CkrAssertionError: Unexpected CK_RV CKR_DEVICE_ERROR; expected one of: CKR_OK

## Other (12)

- **[3]** `test_mldsa_sign` — Invalid ML-DSA sign vector VEC accepted by module
- **[1]** `TestTookanUnwrapAttrs::test_unwrapped_key_cannot_unset_sensitive` — SECURITY: Tookan §N.N — unwrap with CKA_SENSITIVE=False produced a non-sensitive copy of a SENSITIVE=True key.
- **[1]** `TestAESPaddingOracle::test_cbc_pad_all_last_block_positions` — SECURITY: AES-CBC-PAD padding oracle (Vaudenay N) — distinct outcomes {'CKR_ENCRYPTED_DATA_INVALID': N, 'CKR_O
- **[1]** `TestTrustedAttribute::test_user_cannot_set_trusted` — SECURITY: USER session created and was granted CKA_TRUSTED=True on a freshly-generated key — trust boundary br
- **[1]** `TestOutputBufferEdgeCases::test_sign_final_buffer_too_small_then_correct` — After CKR_BUFFER_TOO_SMALL, pulSize must be N (RSA-N); got N
- **[1]** `TestMessageEncrypt::test_message_encrypt_aes_gcm_generated_iv_writeback` — C_EncryptMessage did not write generated IV to pIv
- **[1]** `TestWrapKeyErrors::test_wrapping_key_type_inconsistent` — Module accepted a generic-secret key for AES wrap (expected CKR_WRAPPING_KEY_TYPE_INCONSISTENT)
- **[1]** `TestAllocationGuard::test_generate_key_oom_value_len` — subprocess.TimeoutExpired: Command '['/app/.venv/bin/python', '-c', 'from pkcsN_check.raw.api import RawPKCSN\
- **[1]** `TestMessageEncrypt::test_message_encrypt_aes_ccm_generated_nonce_writeback` — C_EncryptMessage did not write generated nonce
- **[1]** `TestSessionCancel::test_cancel_after_digest_init_subprocess` — Module crashed (signal N) during C_DigestInit/C_SessionCancel - C_SessionCancel not safely callable. Stderr:
