# pkcs11-check Deep Audit & Gap Analysis Design

**Date:** 2026-04-01
**Scope:** Full codebase audit — correctness, coverage, security, maintainability
**Execution:** Ralph-loop autonomous, 42 iterations
**Output:** Per-component report files + code fixes/new tests committed per iteration

## Decisions

- **Approach:** Balanced deep sweep — each iteration audits one component for correctness (spec-check) AND coverage gaps (missing tests), then fixes/implements
- **Execution model:** Ralph-loop autonomous — runs through all iterations, commits as it goes
- **Output:** Report + fixes together — `docs/audit/NN-component.md` per iteration plus direct code changes
- **Scope:** Full implementation — new test files written for uncovered areas, not just stubs

## Ground Truth Sources

- **OASIS specs:** `/home/user/src/m/pkcs11-check-ws/pkcs11/working/doc/spec/*.md` (118 spec files)
- **PKCS#11 v3.2 header:** `third_party/pkcs11-headers/3.2/pkcs11.h` (101KB)
- **NIST ACVP vectors:** `data/acvp/` (fetched via `pkcs11-check fetch-data`)
- **Wycheproof vectors:** `data/wycheproof/` (fetched via `pkcs11-check fetch-data`)

## Iteration Structure

Each iteration follows this sequence:

1. **Load** — read all existing test files and source for the component
2. **Spec-check** — cross-reference against OASIS spec markdown + v3.2 header for parameter correctness, expected behaviors, edge cases
3. **Quality scan** — bare excepts, hardcoded hex, inconsistent CKR handling, missing cleanup
4. **Coverage gap** — identify untested mechanisms, parameter combinations, negative cases, multipart flows
5. **Fix/Implement** — apply corrections, write new tests following existing patterns
6. **Report** — write `docs/audit/NN-component-name.md` with findings, fixes applied, remaining items
7. **Commit** — commit all changes with descriptive message

## Phase Summary

| Phase | Iterations | Focus |
|-------|-----------|-------|
| **1. Foundation & Quality** | 1-3 | Code quality fixes, raw bindings vs header parity, infrastructure audit |
| **2. Symmetric Crypto** | 4-8 | AES modes (incl. CS1/CS3), ACVP vectors, DES/3DES, other ciphers, AEAD |
| **3. Hash & MAC** | 9-11 | SHA/SHA3/BLAKE2/SHAKE, HMAC/CMAC/GMAC/KMAC, ACVP hash vector audit |
| **4. Asymmetric Crypto** | 12-16 | RSA, EC/ECDSA, ECDH/X25519/X448, EdDSA, DSA/DH |
| **5. Post-Quantum** | 17-18 | ML-KEM/ML-DSA, SLH-DSA |
| **6. Key Mgmt & Derivation** | 19-21 | Key lifecycle, KDFs (incl. PBE), key wrapping |
| **7. Session/Token/Object** | 22-24 | Sessions, objects, token/PIN management |
| **8. Advanced & Protocol** | 25-27 | Message API (v3.0+), protocol ops (TLS/SSL/IKE), async + operation state |
| **9. Security & Compliance** | 28-29 | Security audit, CKR compliance spec-check |
| **10. X.509 & Object Types** | 30-32 | Certificates, trust/profile/HW/validation/data objects, OTP/CT-KIP/CMS |
| **11. Legacy & Regional** | 33-34 | GOST cryptography, legacy ciphers (RC/CAST/IDEA/CDMF/Skipjack) |
| **12. Cross-Cutting Concerns** | 35-38 | Interop/cross-verify, multipart/dual-function, threading/stress, access control |
| **13. Remaining Gaps** | 39-41 | HSS/XMSS/domain params, parameter consistency fixes, surface audit & scripts |
| **14. Consolidation** | 42 | Master index, coverage delta, final consistency check |

---

## Phase 1: Foundation & Quality (Iterations 1-3)

### Iteration 1: Code Quality Sweep

**Target files:** All `src/pkcs11_check/` — focus on error handling patterns

**Known issues to fix:**
- Bare `except: pass` in `test_subprocess_safety.py:98`
- Hardcoded hex CKR values: `0x191` (CKR_CRYPTOKI_ALREADY_INITIALIZED) in `ckr/test_ckr_raw_state.py:56`, `ckr/test_ckr_raw_multipart.py:42`, `ckr/_ctypes_raw.py:113`
- Hardcoded `0x69` in `test_tls12.py:922,971`
- Broad `except Exception` blocks in `core/preflight.py`, `core/loader.py`, `core/isolation.py`, `plugin.py`, `compliance_report.py`
- Silent `except Exception: pass` in `test_mech_state.py:121,326`

**Audit scope:**
- Verify every `except` block follows CLAUDE.md rules (specific CKR codes only)
- Ensure all CKR comparisons use symbolic constants from `types_std`
- Check `destroy_quietly()` usage in all test files (currently 1,977 occurrences)
- Verify no PIN values leak into logs or error messages

### Iteration 2: Raw Bindings Parity

**Target files:** `src/pkcs11_check/raw/types_std.py`, `raw/metadata_std.py`, `raw/pack.py`, `raw/pack_mechanisms.py`

**Audit scope:**
- Diff all CKM_* constants against `third_party/pkcs11-headers/3.2/pkcs11.h` — find missing or incorrect values
- Diff all CKA_* constants against header
- Verify all CK_*_PARAMS structures defined in `pack.py`/`pack_mechanisms.py` match header struct definitions (field names, types, sizes)
- Check `metadata_std.py` function signatures match header prototypes
- Verify `extensions.py` v3.0+/v3.2+ function registry completeness
- Cross-reference `attr_metadata.py` attribute type mappings against spec Table 10

### Iteration 3: Infrastructure Audit

**Target files:** `plugin.py`, `fixtures.py`, `raw_fixtures.py`, `config.py`, `markers.py`, `testcases/conftest.py`, `core/collection.py`, `core/test_selection.py`

**Audit scope:**
- Verify `p11_raw_session` fixture handles all session state transitions correctly
- Check for session handle leaks in error paths
- Verify marker definitions cover all v3.2 capabilities
- Audit `mechanism_selection.py` scenario logic against spec mechanism flag tables
- Verify config precedence (CLI > env > TOML > defaults) works correctly for all options
- Check `conftest.py` helper functions for spec-correctness

## Phase 2: Symmetric Crypto (Iterations 4-8)

### Iteration 4: AES Core Modes

**Target files:** `test_encrypt.py`, `test_aes_modes.py`, `test_aes_key_sizes.py`, `test_buffers.py`, `acvp/aes/test_other.py`
**OASIS specs:** `aes.md`, `aes_with_counter.md`, `aes_cbc_with_ciphertext_stealing_cts.md`, `additional_aes_mechanisms.md`, `aes_xts.md`, `general_block_cipher_mechanism_parameters.md`

**Audit scope:**
- Verify ECB, CBC, CTR, OFB, CFB parameter handling matches spec
- **CS1/CS3 issue:** `test_other.py` maps all CBC-CS variants to `CKM_AES_CTS` — add detection logic or per-variant documentation showing which CS variant each module implements
- Verify `ulCounterBits` range validation (spec: 0 < value <= 128)
- Check IV length enforcement per mode
- Add missing padding behavior tests (CBC-PAD vs CBC)
- Verify XTS tweak handling against spec
- Cross-ref `general_block_cipher_mechanism_parameters.md` for shared parameter constraints

### Iteration 5: AES ACVP Vector Audit

**Target files:** `acvp/aes/test_cfb.py`, `test_gcm.py`, `test_ccm.py`, `test_other.py`, `test_wrap.py`, `acvp/aes/base*.py`
**OASIS specs:** AES mechanism specs

**Known consistency issues to investigate:**
- **CCM nonce length**: mechanism_registry uses `nonce_len: 7` default (`_aes.py:259`) but ACVP vectors default to `13` (`test_ccm.py:70,146`) — reconcile
- CCM-ECMA tag length default (8) differs from regular CCM (16) — verify this matches spec
- `mechanism_helpers.py:702` CCM tag_bits conversion may double-convert under edge cases

**Audit scope:**
- Cross-ref all ACVP test groups against NIST ACVP spec format — verify no dropped vectors
- Verify GCM tag length handling (spec allows 4/8/12/13/14/15/16 bytes)
- Verify CCM nonce length constraints (7-13 bytes per spec)
- Check multiblock chaining correctness in test runners
- Add AES-CTR ACVP vectors if absent
- Verify AES-KW/KWP wrapping semantics match NIST SP 800-38F

### Iteration 6: DES/3DES

**Target files:** `test_des.py`
**OASIS specs:** `double_and_triple-length_des.md`, `double_and_triple-length_des_cmac.md`

**Audit scope:**
- Verify DES-ECB, DES-CBC, DES3-ECB, DES3-CBC against spec
- Check key parity bit handling
- Test weak/semi-weak key detection behavior
- Add DES3-CBC-PAD wrap tests (SoftHSM2 reports as broken)
- Verify deprecation handling per v3.2 spec

### Iteration 7: Other Symmetric Ciphers

**Target files:** `test_camellia.py`, `test_aria.py`, `test_seed.py`, `test_blowfish.py`, `test_twofish.py`, `test_salsa20.py`
**OASIS specs:** `camellia.md`, `aria.md`, `seed.md`, `blowfish.md`, `twofish.md`, `salsa20.md`, `chacha20.md`, `chacha20_salsa20_poly1305.md`

**Audit scope:**
- Cross-ref each cipher's parameter structures against OASIS spec
- Verify key size constraints per mechanism
- Check IV/nonce handling per spec requirements
- Add missing CBC-PAD variants where spec defines them
- Verify ChaCha20-Poly1305 nonce/counter semantics against spec
- Check key derivation by data encryption variants against `key_derivation_by_data_encryption-aria.md`, `key_derivation_by_data_encryption-camelia.md`, `key_derivation_by_data_encryption-seed.md`

### Iteration 8: AEAD Deep Audit

**Target files:** `test_aead.py`, `test_authenticated_wrap.py`, relevant acvp/aes tests
**OASIS specs:** AES GCM/CCM specs, `chacha20_salsa20_poly1305.md`, `poly1305.md`

**Audit scope:**
- Verify GCM AAD handling (spec allows empty AAD)
- Verify CCM Adata length encoding rules
- Check tag verification failure behavior (must return `CKR_ENCRYPTED_DATA_INVALID`)
- Test nonce reuse detection if module supports it
- Verify authenticated wrap (v3.2) parameter handling
- Audit Poly1305 standalone usage against `poly1305.md`

## Phase 3: Hash & MAC (Iterations 9-11)

### Iteration 9: Hash Functions

**Target files:** `test_digest.py`, `test_sha3.py`, `test_blake2.py`, `test_mech_digest.py`, `test_hash_ml_dsa.py`, `test_hash_slh_dsa.py`
**OASIS specs:** `digests.md`

**Audit scope:**
- Verify digest output sizes match spec for all SHA variants
- Implement SHAKE-128/256 XOF tests using `C_DigestXof` (currently TODO)
- Verify BLAKE2b/BLAKE2s parameter handling (key, salt, personalization)
- Add multipart digest streaming tests for all hash algorithms
- Check `C_DigestKey` behavior for HMAC key digesting

### Iteration 10: MAC Operations

**Target files:** `test_mech_sign.py` (HMAC portions), related mechanism tests
**OASIS specs:** `hmac_mechanisms.md`, `hash_based_message_authentication_codes.md`, `aes_cmac.md`, `kmac.md`, `poly1305.md`

**Audit scope:**
- Verify HMAC key size constraints per spec (minimum = hash output size)
- Test HMAC_GENERAL output truncation behavior
- Add KMAC-128/256 tests against `kmac.md` spec
- Verify CMAC with AES/3DES key types
- Check GMAC tag generation/verification

### Iteration 11: ACVP Hash/HMAC Audit

**Target files:** `acvp/test_acvp_hash.py`, `acvp/test_acvp_hmac.py`, `acvp/test_acvp_sha3.py`

**Audit scope:**
- Verify all ACVP test groups are exercised (no silently skipped groups)
- Cross-ref hash output values against NIST expected outputs
- Check Monte Carlo test implementation correctness if present
- Verify large-message digest handling

## Phase 4: Asymmetric Crypto (Iterations 12-16)

### Iteration 12: RSA Operations

**Target files:** `test_rsa_extended.py`, `test_rsa_oaep.py`, `test_rsa_key_import.py`, `test_rsa_key_wrapping.py`, `acvp/test_acvp_rsa*.py`, `wycheproof/test_wycheproof_rsa*.py`
**OASIS specs:** `rsa.md`

**Known consistency issues:**
- `test_rsa_extended.py:185,295,320,589` — hardcoded 256-byte output size assumes RSA-2048; should derive from key size

**Audit scope:**
- Verify keygen parameter validation (modulus bits, public exponent)
- Verify PKCS#1 v1.5 sign/verify against spec
- Verify PSS salt length handling (spec: 0 to hash_len, or -1 for max)
- Verify OAEP hash/MGF algorithm combinations against spec Table
- Check RSA X.509 raw encrypt semantics (NSS known bug)
- Cross-ref ACVP and Wycheproof vectors for completeness
- Fix hardcoded output size assumptions

### Iteration 13: EC/ECDSA

**Target files:** `test_ec_curves.py`, `test_ecdsa_extended.py`, `test_ec_import_export.py`, `acvp/test_acvp_ecdsa.py`, `wycheproof/test_wycheproof_ecdsa.py`
**OASIS specs:** `elliptic_curves.md`

**Audit scope:**
- Verify curve OID correctness for all named curves
- Check EC point encoding/decoding (compressed vs uncompressed)
- Verify ECDSA hash mechanism pairing per spec
- Test boundary cases: point at infinity, invalid curve points
- Verify `CK_ECDSA_SIG` format (r||s concatenation)

### Iteration 14: ECDH/X25519/X448

**Target files:** `test_ecdh_extended.py`, `test_ecdh_known_answer.py`, `test_dh_key_agreement.py`, `test_x942_dh.py`, `acvp/test_acvp_ecdh.py`, `wycheproof/test_wycheproof_ecdh.py`, `wycheproof/test_wycheproof_x25519.py`
**OASIS specs:** `elliptic_curves.md`, `diffie-hellman.md`

**Audit scope:**
- Verify `CK_ECDH1_DERIVE_PARAMS` structure (KDF, shared data, public data)
- Check cofactor ECDH vs standard ECDH
- Verify X25519 key agreement semantics
- Add X448 tests if missing
- Verify KDF chaining (ECDH + SHA256 derive)

### Iteration 15: EdDSA

**Target files:** `test_eddsa.py`, `test_cctv_ed25519.py`, `acvp/test_acvp_eddsa.py`, `wycheproof/test_wycheproof_ed25519.py`
**OASIS specs:** `elliptic_curves.md` (EdDSA section)

**Audit scope:**
- Verify Ed25519/Ed448 sign/verify parameter handling
- Check `CK_EDDSA_PARAMS` context parameter (NSS rejects this — spec violation)
- Test pre-hash EdDSA (Ed25519ph/Ed448ph) if spec defines it
- Verify signature format (64 bytes for Ed25519, 114 for Ed448)

### Iteration 16: DSA/DH

**Target files:** `test_dsa_complete.py`, `test_dh_key_agreement.py`, `wycheproof/test_wycheproof_dsa.py`
**OASIS specs:** `dsa.md`, `diffie-hellman.md`, `extended_triple_diffie-hellman.md`

**Audit scope:**
- Verify DSA parameter generation (L/N pairs per FIPS 186-4)
- Check DH domain parameter handling
- Verify DSA signature format
- Test parameter validation edge cases
- Audit Extended Triple Diffie-Hellman (X3DH) against `extended_triple_diffie-hellman.md`

## Phase 5: Post-Quantum (Iterations 17-18)

### Iteration 17: ML-KEM & ML-DSA

**Target files:** `test_kem.py`, `test_pqc_sign.py`, `test_mech_kem.py`, `acvp/test_acvp_mlkem.py`, `acvp/test_acvp_mldsa.py`, `wycheproof/test_wycheproof_mlkem.py`, `wycheproof/test_wycheproof_mldsa*.py`
**OASIS specs:** `ml-kem.md`, `ml_dsa.md`

**Audit scope:**
- Verify parameter set handling (ML-KEM-512/768/1024, ML-DSA-44/65/87)
- Check `C_EncapsulateKey`/`C_DecapsulateKey` semantics (v3.2)
- Address TODO: `CK_SIGN_ADDITIONAL_CONTEXT` parameter for ML-DSA context
- Cross-ref ACVP vectors for all parameter sets
- Verify shared secret sizes per parameter set

### Iteration 18: SLH-DSA

**Target files:** `test_pqc_sign.py`, `test_hash_slh_dsa.py`, `acvp/test_acvp_slhdsa.py`
**OASIS specs:** `slh-dsa.md`

**Audit scope:**
- Verify all SLH-DSA parameter sets (SHA2-128s/f, SHA2-192s/f, SHA2-256s/f, SHAKE-128s/f, SHAKE-192s/f, SHAKE-256s/f)
- Check signature size correctness per parameter set
- Verify ACVP vector coverage completeness
- Test hash-then-sign mode

## Phase 6: Key Management & Derivation (Iterations 19-21)

### Iteration 19: Key Lifecycle

**Target files:** `test_keymgmt.py`, `test_key_lifecycle.py`, `test_key_flags.py`, `test_key_sizes.py`, `test_key_usage_policy.py`, `test_sensitivity.py`, `test_handle_reuse.py`
**OASIS specs:** `key_objects.md`, `private_key_objects.md`, `public_key_objects.md`, `secret_key_objects.md`, `key_management_functions.md`

**Audit scope:**
- Verify CKA_EXTRACTABLE/CKA_SENSITIVE transitions per spec (one-way)
- Check CKA_WRAP_WITH_TRUSTED enforcement
- Verify key attribute defaults per spec Table 10
- Test `C_CopyObject` attribute propagation rules
- Check Tookan vulnerability mitigations (CKA_EXTRACTABLE escalation)

### Iteration 20: KDF Operations

**Target files:** `test_kdf.py`, `test_misc_kdf.py`, `test_sp800_108_kdf.py`, `test_hkdf_extended.py`, `test_pbe.py`, `wycheproof/test_wycheproof_hkdf.py`, `wycheproof/test_wycheproof_pbkdf2.py`, `wycheproof/test_wycheproof_pbes2.py`
**OASIS specs:** `hash_based_key_derivations.md`, `hkdf_mechanisms.md`, `sp800-108_key_derivation.md`, `miscellaneous_simple_key_derivation_mechanisms.md`, `password-based_encryption.md`, `pkcs12_password-based_encryption-authentication.md`, `key_derivation_by_data_encryption_aes-des.md`

**Audit scope:**
- Verify HKDF extract/expand parameter handling against RFC 5869
- Check PBKDF2 iteration count enforcement
- Verify SP800-108 KDF modes (counter, feedback, pipeline)
- Add SHA3-based KDF key derivation tests (SHA3_* key derive mechanisms — currently untested)
- Check `CK_SP800_108_KDF_PARAMS` structure correctness
- Audit PBE mechanisms (MD2/MD5/SHA1 + DES/RC2/RC4 combos) against `password-based_encryption.md`
- Cross-ref PKCS#12 PBE against `pkcs12_password-based_encryption-authentication.md`

### Iteration 21: Key Wrapping

**Target files:** `test_mech_wrap.py`, `test_authenticated_wrap.py`, `test_rsa_key_wrapping.py`, `acvp/aes/test_wrap.py`
**OASIS specs:** `aes_key_wrap.md`, `wrapping-unwrapping_private_keys.md`

**Audit scope:**
- Verify AES-KW semantics (64-bit IV, 8-byte blocks per RFC 3394)
- Verify AES-KWP with padding (RFC 5649)
- Check RSA wrap parameter handling
- Implement v3.2 `C_WrapKeyAuthenticated`/`C_UnwrapKeyAuthenticated` tests if missing
- Verify wrap/unwrap attribute template propagation
- Cross-ref private key wrapping format against `wrapping-unwrapping_private_keys.md`

## Phase 7: Session/Token/Object (Iterations 22-24)

### Iteration 22: Session Management

**Target files:** `test_session_*.py` (6 files), `test_concurrent_sessions.py`, `test_v30_session.py`, `test_ro_session*.py`
**OASIS specs:** `session_mgmt_functions.md`

**Audit scope:**
- Verify state machine transitions against OASIS spec Figure 3 (all 5 states)
- Check R/O session restrictions per spec
- Test session info field correctness
- Verify concurrent session limits and behavior
- Check v3.0 session changes
- Verify `callback_functions.md` — notification/surrender callback handling

### Iteration 23: Object Management

**Target files:** `test_object.py`, `test_object_*.py` (4 files), `test_search.py`, `test_data_objects.py`, `test_token_objects.py`, `test_validation_objects.py`, `test_set_attribute.py`, `test_attribute_*.py`
**OASIS specs:** `objects.md`, `object_classification.md`, `creating_objects.md`, `object_mgmt_functions.md`, `common_attributes.md`, `storage_objects.md`

**Audit scope:**
- Verify attribute default values against spec per object class
- Check `C_FindObjects` template matching semantics
- Verify session vs token object visibility rules
- Test `C_GetAttributeValue` with `CK_UNAVAILABLE_INFORMATION`
- Check `C_SetAttributeValue` restriction rules per spec
- Verify `creating_objects.md` rules for each object class

### Iteration 24: Token & PIN Management

**Target files:** `test_pin.py`, `test_so_pin.py`, `test_token_flags.py`, `test_init.py`
**OASIS specs:** `slot_and_token_mgmt_functions.md`

**Audit scope:**
- Verify `C_InitToken` behavior per spec (clears all objects except SO PIN)
- Check `C_InitPIN`/`C_SetPIN` parameter validation
- Verify token flags correctness per spec
- Test SO login/operations separation from USER

## Phase 8: Advanced & Protocol (Iterations 25-27)

### Iteration 25: Message-Based API (v3.0+)

**Target files:** `test_message_crypto.py`, `test_mech_message.py`
**OASIS specs:** `message_based_encryption_functions.md`, `message_based_decryption_functions.md`, `message-based_signing_and_macing_functions.md`, `message-based_functions_for_verifying_signatures_and_macs.md`

**Audit scope:**
- Verify `C_MessageEncryptInit`/`C_EncryptMessage`/`C_EncryptMessageBegin`/`C_EncryptMessageNext` flow
- Same for decrypt, sign, verify message operations
- Check multi-message session semantics
- Verify message operation and single-part operation interaction
- Add comprehensive tests if coverage thin
- Verify GCM message params (no `ulIvBits` in `CK_GCM_MESSAGE_PARAMS` vs `CK_AES_GCM_PARAMS`)

### Iteration 26: Protocol Operations

**Target files:** `test_tls12.py`, `test_ssl3.py`, `test_wtls.py`, `test_ike.py`, `test_x942_dh.py`, `test_x3dh.py`, `test_double_ratchet.py`, `test_protocol_edge_cases.py`
**OASIS specs:** `tls_1.2_mechanisms.md`, `ssl.md`, `wtls.md`, `ike_mechanisms.md`, `double_ratchet.md`, `ct-kip.md`

**Audit scope:**
- Fix hardcoded `0x69` in `test_tls12.py` — replace with symbolic constant
- Verify TLS 1.2 PRF parameter structure against spec
- Check SSL3 key material derivation parameters
- Verify IKE mechanism parameter handling
- Cross-ref X3DH and Double Ratchet implementations against Signal spec and `double_ratchet.md`
- Audit protocol edge cases file

### Iteration 27: Async & Operation State

**Target files:** `test_operation_state.py`, `test_remaining_gaps.py` (async TODO)
**OASIS specs:** `asynchronous_function_management_functions.md`, `parallel_function_management_functions.md`

**Audit scope:**
- Implement async lifecycle test (currently TODO in `test_remaining_gaps.py:409`)
- Verify `C_GetOperationState`/`C_SetOperationState` for digest, encrypt, sign operations
- Test operation state portability across sessions
- Check v3.0+ `C_SessionCancel` behavior
- Audit parallel function management against spec

## Phase 9: Security & Compliance (Iterations 28-29)

### Iteration 28: Security Audit

**Target files:** `test_padding_oracle.py`, `test_nonce_quality.py`, `test_tookan.py`, `test_api_security.py`, `test_fuzz.py`, `test_attribute_fuzz.py`, `test_mechanism_fuzz.py`, `test_cve_regression.py`
**OASIS specs:** `security_and_privacy_considerations.md`

**Audit scope:**
- Verify padding oracle test methodology
- Check nonce randomness statistical tests adequacy
- Cross-ref Tookan attack vectors against paper
- Verify CVE regression tests cover all documented CVEs in `docs/cve-regression.md`
- Add missing security-sensitive negative tests
- Check for timing side-channel test opportunities
- Cross-ref `security_and_privacy_considerations.md` for any untested security requirements

### Iteration 29: CKR Compliance

**Target files:** All 30 files in `testcases/ckr/`
**OASIS specs:** `function_return_values.md`, mechanism-specific error tables throughout spec

**Audit scope:**
- Cross-ref every expected CKR return code against OASIS spec
- Verify error priority ordering per spec (e.g., `CKR_SESSION_HANDLE_INVALID` before `CKR_ARGUMENTS_BAD`)
- Check `_ckr_spec.py` specification data correctness
- Verify all CKR codes from `types_std.py` have test coverage
- Fix any incorrect CKR expectations

## Phase 10: X.509 & Object Types (Iterations 30-32)

### Iteration 30: X.509 Certificate Handling

**Target files:** `x509/test_attributes.py`, `x509/test_core_ops.py`, `x509/test_identity.py`, `x509/test_lifecycle.py`, `x509/test_search.py`, `x509/test_attribute_parity.py`, `x509/test_limbo_import.py`, `x509/test_limbo_stress.py`, `x509/conftest.py`
**OASIS specs:** `certificate_objects.md`

**Audit scope:**
- Verify certificate attribute handling (CKA_SUBJECT, CKA_ISSUER, CKA_SERIAL_NUMBER, CKA_VALUE) against spec
- Check X.509 certificate import/create template requirements
- Verify certificate search semantics (by subject, issuer, serial)
- Audit Limbo test vectors for edge-case certificate parsing
- Verify attribute parity between certificate and extracted public key
- Cross-ref certificate object class rules from `certificate_objects.md`

### Iteration 31: Trust, Profile, HW Feature, Validation & Data Objects

**Target files:** `test_trust_objects.py`, `test_profiles.py`, `test_hw_features.py`, `test_validation_objects.py`, `test_data_objects.py`, `test_large_objects.py`, `test_generic_secret.py`
**OASIS specs:** `trust_objects.md`, `profile_objects.md`, `hardware_feature_objects.md`, `validation_objects.md`, `data_objects.md`, `generic_secret_key.md`

**Audit scope:**
- Verify trust object attributes and CKA_WRAP_WITH_TRUSTED policy against `trust_objects.md`
- Audit profile compliance tests against `profile_objects.md` — verify all v3.2 profiles tested
- Check hardware feature object handling (CKO_HW_FEATURE, clock, counter) against `hardware_feature_objects.md`
- Verify validation object attributes against `validation_objects.md`
- Check data object create/read/search against `data_objects.md`
- Verify generic secret key handling against `generic_secret_key.md`
- Test large object storage limits and behavior

### Iteration 32: OTP, CT-KIP & CMS Mechanisms

**Target files:** `test_otp.py`, `test_cms.py`
**OASIS specs:** `otp_mechanisms.md`, `otp_key_objects.md`, `ct-kip.md`, `cms_mechanisms.md`

**Audit scope:**
- Verify OTP key object attributes against `otp_key_objects.md`
- Audit OTP mechanisms (SECURID, HOTP, ACTI) against `otp_mechanisms.md`
- Check CKM_CMS_SIG mechanism handling against `cms_mechanisms.md`
- Audit CT-KIP mechanism parameters against `ct-kip.md`
- Add tests for any missing OTP/CMS operations

## Phase 11: Legacy & Regional (Iterations 33-34)

### Iteration 33: GOST Cryptography

**Target files:** `test_gost.py`, `mechanism_registry/_misc.py` (GOST entries)
**OASIS specs:** `gost_28147-89.md`, `gost_r_34.10-2001.md`, `gost_r_34.11-94.md`

**Audit scope:**
- Verify GOST 28147-89 (block cipher) parameters against spec
- Check GOST R 34.10-2001 (digital signature) keygen/sign/verify against spec
- Verify GOST R 34.11-94 (hash) digest operation against spec
- Test GOST key derivation mechanisms
- Add missing GOST mechanism tests where modules support them

### Iteration 34: Legacy Ciphers

**Target files:** `mechanism_registry/_legacy.py`, `test_remaining_gaps.py` (legacy sections)
**OASIS specs:** (deprecated mechanism references in spec)

**Registered but untested mechanism families (82 mechanisms):**
- RC2 (CKM_RC2_*: ECB, CBC, MAC, key gen) — 9 mechanisms
- RC4 (CKM_RC4_*: key gen, stream) — 3 mechanisms
- RC5 (CKM_RC5_*: ECB, CBC, MAC, key gen) — 8 mechanisms
- CAST/CAST3/CAST128 (CKM_CAST*: ECB, CBC, MAC, key gen) — 18 mechanisms
- IDEA (CKM_IDEA_*: ECB, CBC, MAC, key gen) — 6 mechanisms
- CDMF (CKM_CDMF_*) — 6 mechanisms
- Skipjack (CKM_SKIPJACK_*) — 5 mechanisms
- BATON (CKM_BATON_*) — 7 mechanisms
- JUNIPER (CKM_JUNIPER_*) — 6 mechanisms
- KEA/Fortezza (CKM_KEA_*, CKM_FORTEZZA_*) — 4 mechanisms
- Other legacy wrapping (CKM_KEY_WRAP_LYNKS, CKM_KEY_WRAP_SET_OAEP) — 2+ mechanisms

**Audit scope:**
- Verify legacy mechanism constant values against header
- Document which modules support which legacy mechanisms
- Add basic smoke tests for any supported legacy mechanisms (keygen + encrypt roundtrip)
- Mark unsupported mechanisms with proper skip conditions
- Note deprecation status per v3.2 spec

## Phase 12: Cross-Cutting Concerns (Iterations 35-38)

### Iteration 35: Interoperability & Cross-Verification

**Target files:** `test_interop.py`, `test_interop_openssl.py`, `test_crossverify.py`, `test_crossverify_extended.py`, `test_metamorphic.py`

**Audit scope:**
- Verify cross-library key import/export roundtrips (PKCS#11 <-> OpenSSL)
- Check cross-verification test correctness (encrypt with module A, decrypt with module B pattern)
- Audit metamorphic relation tests for mathematical correctness
- Verify interop test isolation (no cross-contamination between module states)
- Add missing cross-verify scenarios for PQC algorithms

### Iteration 36: Multipart, Dual-Function & Stateful Operations

**Target files:** `test_multipart.py`, `test_multipart_streaming.py`, `test_dual_function.py`, `test_mech_multipart.py`, `test_mech_state.py`, `test_stateful_sigs.py`
**OASIS specs:** `dual-function_cryptographic_functions.md`, `encryption_functions.md` (multipart sections), `signing_and_macing_functions.md` (multipart sections)

**Audit scope:**
- Verify multipart encrypt/decrypt update+final sequences against spec
- Check streaming digest update correctness with various chunk sizes
- Audit dual-function operations (`C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate`) against `dual-function_cryptographic_functions.md`
- Verify operation state machine transitions (init -> update -> final, with error recovery)
- Check stateful signature scheme handling (HSS/XMSS state management)

### Iteration 37: Threading, Stress & Resource Exhaustion

**Target files:** `test_threading.py`, `test_stress.py`, `test_resource.py`, `test_session_exhaustion.py`, `test_benchmark.py`

**Audit scope:**
- Verify thread safety tests use proper locking where required by spec
- Check stress test patterns for correctness (1000-cycle ops, DB concurrent writes)
- Audit resource exhaustion tests (handle limits, memory limits, session limits)
- Verify session exhaustion cleanup behavior
- Review benchmark tests for measurement methodology correctness
- Add stress tests for PQC operations if missing

### Iteration 38: Access Control & Visibility

**Target files:** `test_access.py`, `test_access_control.py`, `test_access_levels.py`, `test_object_visibility.py`, `test_ro_session.py`, `test_ro_session_restrictions.py`
**OASIS specs:** `objects.md` (access control sections), `session_mgmt_functions.md` (R/O restrictions)

**Audit scope:**
- Verify R/O session cannot create/modify token objects per spec
- Check private object visibility rules (requires login)
- Verify CKA_PRIVATE attribute enforcement
- Test access level transitions (public -> private) with login/logout
- Verify object access across sessions (same token, different sessions)
- Check sensitive attribute read restrictions

## Phase 13: Remaining Gaps (Iterations 39-41)

### Iteration 39: HSS/XMSS, Domain Parameters & Mechanism Objects

**Target files:** `test_domain_params.py`, `test_mechanism.py`, `test_mechanism_objects.py`, `test_remaining_gaps.py`
**OASIS specs:** `hss.md`, `xmss_and_xmss-mt.md`, `domain_parameter_objects.md`, `mechanism_objects.md`

**Audit scope:**
- Audit HSS (Hierarchical Signature Scheme) mechanism handling against `hss.md`
- Audit XMSS/XMSS-MT mechanisms against `xmss_and_xmss-mt.md`
- Verify domain parameter object create/read for DSA/DH against `domain_parameter_objects.md`
- Check mechanism object attributes against `mechanism_objects.md`
- Review `test_remaining_gaps.py` — implement or document all remaining TODOs

### Iteration 40: Parameter Consistency Fixes

**Target files:** All `mechanism_registry/*.py`, `mechanism_helpers.py`, `raw/recipes.py`, `raw/pack.py`, `raw/pack_mechanisms.py`

**Known issues from gap analysis:**
- CCM nonce_len default mismatch (registry=7, ACVP=13)
- Hardcoded RSA output sizes in `test_rsa_extended.py`
- `mechanism_helpers.py:702` CCM tag_bits double-conversion risk
- TODO items: SHAKE mechanism IDs hardcoded in `test_mech_digest.py:51-52`, `test_mech_multipart.py:148-149`, `mechanism_registry/_hash.py:189`

**Audit scope:**
- Reconcile all parameter defaults between mechanism_registry, ACVP loaders, and mechanism_helpers
- Fix all hardcoded numeric values that should use symbolic constants
- Verify `recipes.py` helper default values match spec
- Verify `pack.py`/`pack_mechanisms.py` parameter packing matches header struct layouts
- Resolve all SHAKE-related TODOs (hardcoded IDs pending spec revision)
- Cross-check all `# type: ignore` comments for correctness (111 instances)

### Iteration 41: Surface Audit, Scripts & Tooling

**Target files:** `test_surface_audit.py`, `test_tool_templates.py`, `scripts/*.py`

**Audit scope:**
- Verify surface audit probes cover all v3.2 mechanism families
- Check `scripts/mechanism-audit.py` correctness — compare its output against our findings
- Verify `scripts/ckr-coverage-check.py` accuracy
- Audit `scripts/mechanism_coverage.py` and `scripts/mechanism-matrix.py` for completeness
- Check `scripts/generate_raw_standard.py` — verify it correctly parses v3.2 header
- Review `test_tool_templates.py` for template correctness
- Verify `scripts/check_raw_exports.py` catches all expected exports

## Phase 14: Consolidation (Iteration 42)

### Iteration 42: Final Consolidation

**Actions:**
- Generate master index `docs/audit/00-index.md` linking all 41 iteration reports
- Aggregate statistics: findings count, fixes applied, new tests written, remaining items
- Cross-module consistency check: ensure patterns are consistent across all test files
- Generate coverage delta: mechanisms/functions covered before vs after audit
- Verify no regressions: `uv run python -m pytest tests/` (meta-tests must still pass)
- List items deferred for future work
- Update `docs/module-issues.md` if new module-specific findings discovered

## Ralph-Loop Configuration

- **Interval:** Per-iteration (not time-based) — each iteration is one ralph-loop cycle
- **Stop condition:** All 42 iterations complete, or user cancels
- **Commit strategy:** One commit per iteration with message format: `audit(NN): component-name — summary of changes`
- **Error handling:** If an iteration encounters a blocker, document it in the report and move to next iteration

## Pre-Audit Checklist

Before starting the ralph-loop:
1. Ensure `dev` branch is clean (no uncommitted changes)
2. Create `docs/audit/` directory
3. Verify OASIS spec files accessible at `/home/user/src/m/pkcs11-check-ws/pkcs11/working/doc/spec/`
4. Verify test data available (`uv run pkcs11-check fetch-data --status`)
5. Run `uv run python -m pytest tests/` to establish baseline meta-test results

## OASIS Spec File Mapping

Complete mapping of iteration to spec files for reference:

| Spec File | Iteration(s) |
|-----------|-------------|
| `aes.md`, `aes_with_counter.md`, `aes_cbc_with_ciphertext_stealing_cts.md` | 4, 5 |
| `aes_key_wrap.md`, `aes_xts.md`, `additional_aes_mechanisms.md` | 4, 5, 21 |
| `aes_cmac.md` | 10 |
| `aria.md`, `blowfish.md`, `camellia.md`, `seed.md`, `twofish.md` | 7 |
| `chacha20.md`, `salsa20.md`, `chacha20_salsa20_poly1305.md` | 7, 8 |
| `double_and_triple-length_des.md`, `double_and_triple-length_des_cmac.md` | 6 |
| `digests.md` | 9 |
| `hmac_mechanisms.md`, `hash_based_message_authentication_codes.md` | 10 |
| `kmac.md`, `poly1305.md` | 10 |
| `rsa.md` | 12 |
| `elliptic_curves.md` | 13, 14, 15 |
| `dsa.md`, `diffie-hellman.md` | 16 |
| `extended_triple_diffie-hellman.md` | 16 |
| `ml-kem.md`, `ml_dsa.md`, `slh-dsa.md` | 17, 18 |
| `hss.md`, `xmss_and_xmss-mt.md` | 39 |
| `hash_based_key_derivations.md`, `hkdf_mechanisms.md` | 20 |
| `sp800-108_key_derivation.md`, `miscellaneous_simple_key_derivation_mechanisms.md` | 20 |
| `password-based_encryption.md`, `pkcs12_password-based_encryption-authentication.md` | 20 |
| `key_derivation_by_data_encryption_aes-des.md`, `-aria.md`, `-camelia.md`, `-seed.md` | 7, 20 |
| `wrapping-unwrapping_private_keys.md` | 21 |
| `session_mgmt_functions.md` | 22 |
| `objects.md`, `object_classification.md`, `creating_objects.md` | 23 |
| `object_mgmt_functions.md`, `common_attributes.md`, `storage_objects.md` | 23 |
| `slot_and_token_mgmt_functions.md` | 24 |
| `certificate_objects.md` | 30 |
| `trust_objects.md`, `profile_objects.md`, `hardware_feature_objects.md` | 31 |
| `validation_objects.md`, `data_objects.md`, `generic_secret_key.md` | 31 |
| `domain_parameter_objects.md`, `mechanism_objects.md` | 39 |
| `otp_mechanisms.md`, `otp_key_objects.md` | 32 |
| `cms_mechanisms.md`, `ct-kip.md` | 32 |
| `gost_28147-89.md`, `gost_r_34.10-2001.md`, `gost_r_34.11-94.md` | 33 |
| `tls_1.2_mechanisms.md`, `ssl.md`, `wtls.md` | 26 |
| `ike_mechanisms.md`, `double_ratchet.md` | 26 |
| `message_based_*_functions.md` (4 files) | 25 |
| `asynchronous_function_management_functions.md` | 27 |
| `parallel_function_management_functions.md` | 27 |
| `dual-function_cryptographic_functions.md` | 36 |
| `encryption_functions.md`, `decryption_functions.md` | 4, 36 |
| `signing_and_macing_functions.md`, `functions_for_verifying_signatures_and_macs.md` | 10, 36 |
| `message_digesting_functions.md` | 9 |
| `random_number_generation_functions.md` | 28 |
| `key_management_functions.md` | 19 |
| `function_return_values.md` | 29 |
| `security_and_privacy_considerations.md` | 28 |
| `general_block_cipher_mechanism_parameters.md` | 4 |
| `general_data_types.md`, `general_purpose_functions.md` | 2, 3 |
| `conventions_for_functions_output.md` | 2 |
| `callback_functions.md` | 22 |
| `null_mechanism.md` | 40 |
| `key_objects.md`, `private_key_objects.md`, `public_key_objects.md`, `secret_key_objects.md` | 19 |
