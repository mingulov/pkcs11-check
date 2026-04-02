# pkcs11-check Deep Audit & Gap Analysis Design

**Date:** 2026-04-01
**Scope:** Full codebase audit — correctness, coverage, security, maintainability
**Execution:** Ralph-loop autonomous, 30 iterations
**Output:** Per-component report files + code fixes/new tests committed per iteration

## Decisions

- **Approach:** Balanced deep sweep — each iteration audits one component for correctness (spec-check) AND coverage gaps (missing tests), then fixes/implements
- **Execution model:** Ralph-loop autonomous — runs through all iterations, commits as it goes
- **Output:** Report + fixes together — `docs/audit/NN-component.md` per iteration plus direct code changes
- **Scope:** Full implementation — new test files written for uncovered areas, not just stubs

## Ground Truth Sources

- **OASIS specs:** `/home/user/src/m/pkcs11-check-ws/pkcs11/working/doc/spec/*.md` (150+ mechanism spec files)
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
**OASIS specs:** `aes_with_counter.md`, `aes_cbc_with_ciphertext_stealing_cts.md`, `additional_aes_mechanisms.md`

**Audit scope:**
- Verify ECB, CBC, CTR, OFB, CFB parameter handling matches spec
- **CS1/CS3 issue:** `test_other.py` maps all CBC-CS variants to `CKM_AES_CTS` — add detection logic or per-variant documentation showing which CS variant each module implements
- Verify `ulCounterBits` range validation (spec: 0 < value <= 128)
- Check IV length enforcement per mode
- Add missing padding behavior tests (CBC-PAD vs CBC)
- Verify XTS tweak handling against spec

### Iteration 5: AES ACVP Vector Audit

**Target files:** `acvp/aes/test_cfb.py`, `test_gcm.py`, `test_ccm.py`, `test_other.py`, `test_wrap.py`, `acvp/aes/base*.py`
**OASIS specs:** AES mechanism specs

**Audit scope:**
- Cross-ref all ACVP test groups against NIST ACVP spec format — verify no dropped vectors
- Verify GCM tag length handling (spec allows 4/8/12/13/14/15/16 bytes)
- Verify CCM nonce length constraints (7-13 bytes per spec)
- Check multiblock chaining correctness in test runners
- Add AES-CTR ACVP vectors if absent
- Verify AES-KW/KWP wrapping semantics match NIST SP 800-38F

### Iteration 6: DES/3DES

**Target files:** `test_des.py`
**OASIS specs:** `des*.md`

**Audit scope:**
- Verify DES-ECB, DES-CBC, DES3-ECB, DES3-CBC against spec
- Check key parity bit handling
- Test weak/semi-weak key detection behavior
- Add DES3-CBC-PAD wrap tests (SoftHSM2 reports as broken)
- Verify deprecation handling per v3.2 spec

### Iteration 7: Other Symmetric Ciphers

**Target files:** `test_camellia.py`, `test_aria.py`, `test_seed.py`, `test_blowfish.py`, `test_twofish.py`, `test_salsa20.py`, `test_gost.py`
**OASIS specs:** Respective mechanism specs

**Audit scope:**
- Cross-ref each cipher's parameter structures against OASIS spec
- Verify key size constraints per mechanism
- Check IV/nonce handling per spec requirements
- Add missing CBC-PAD variants where spec defines them
- Verify ChaCha20-Poly1305 nonce/counter semantics against spec

### Iteration 8: AEAD Deep Audit

**Target files:** `test_aead.py`, `test_authenticated_wrap.py`, relevant acvp/aes tests
**OASIS specs:** `aes_gcm*.md`, `aes_ccm*.md`, `chacha20*.md`

**Audit scope:**
- Verify GCM AAD handling (spec allows empty AAD)
- Verify CCM Adata length encoding rules
- Check tag verification failure behavior (must return `CKR_ENCRYPTED_DATA_INVALID`)
- Test nonce reuse detection if module supports it
- Verify authenticated wrap (v3.2) parameter handling

## Phase 3: Hash & MAC (Iterations 9-11)

### Iteration 9: Hash Functions

**Target files:** `test_digest.py`, `test_sha3.py`, `test_blake2.py`, `test_mech_digest.py`, `test_hash_ml_dsa.py`, `test_hash_slh_dsa.py`
**OASIS specs:** `sha*.md`, `blake2*.md`, `sha3*.md`

**Audit scope:**
- Verify digest output sizes match spec for all SHA variants
- Implement SHAKE-128/256 XOF tests using `C_DigestXof` (currently TODO)
- Verify BLAKE2b/BLAKE2s parameter handling (key, salt, personalization)
- Add multipart digest streaming tests for all hash algorithms
- Check `C_DigestKey` behavior for HMAC key digesting

### Iteration 10: MAC Operations

**Target files:** `test_mech_sign.py` (HMAC portions), related mechanism tests
**OASIS specs:** `hmac*.md`, `cmac*.md`, `gmac*.md`

**Audit scope:**
- Verify HMAC key size constraints per spec (minimum = hash output size)
- Test HMAC_GENERAL output truncation behavior
- Add KMAC-128/256 tests if not present
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
**OASIS specs:** `rsa*.md`, `pkcs*.md`

**Audit scope:**
- Verify keygen parameter validation (modulus bits, public exponent)
- Verify PKCS#1 v1.5 sign/verify against spec
- Verify PSS salt length handling (spec: 0 to hash_len, or -1 for max)
- Verify OAEP hash/MGF algorithm combinations against spec Table
- Check RSA X.509 raw encrypt semantics (NSS known bug)
- Cross-ref ACVP and Wycheproof vectors for completeness

### Iteration 13: EC/ECDSA

**Target files:** `test_ec_curves.py`, `test_ecdsa_extended.py`, `test_ec_import_export.py`, `acvp/test_acvp_ecdsa.py`, `wycheproof/test_wycheproof_ecdsa.py`
**OASIS specs:** `ec*.md`, `ecdsa*.md`

**Audit scope:**
- Verify curve OID correctness for all named curves
- Check EC point encoding/decoding (compressed vs uncompressed)
- Verify ECDSA hash mechanism pairing per spec
- Test boundary cases: point at infinity, invalid curve points
- Verify `CK_ECDSA_SIG` format (r||s concatenation)

### Iteration 14: ECDH/X25519/X448

**Target files:** `test_ecdh_extended.py`, `test_ecdh_known_answer.py`, `test_dh_key_agreement.py`, `test_x942_dh.py`, `acvp/test_acvp_ecdh.py`, `wycheproof/test_wycheproof_ecdh.py`, `wycheproof/test_wycheproof_x25519.py`
**OASIS specs:** `ecdh*.md`, `x25519*.md`, `dh*.md`

**Audit scope:**
- Verify `CK_ECDH1_DERIVE_PARAMS` structure (KDF, shared data, public data)
- Check cofactor ECDH vs standard ECDH
- Verify X25519 key agreement semantics
- Add X448 tests if missing
- Verify KDF chaining (ECDH + SHA256 derive)

### Iteration 15: EdDSA

**Target files:** `test_eddsa.py`, `test_cctv_ed25519.py`, `acvp/test_acvp_eddsa.py`, `wycheproof/test_wycheproof_ed25519.py`
**OASIS specs:** `eddsa*.md`

**Audit scope:**
- Verify Ed25519/Ed448 sign/verify parameter handling
- Check `CK_EDDSA_PARAMS` context parameter (NSS rejects this — spec violation)
- Test pre-hash EdDSA (Ed25519ph/Ed448ph) if spec defines it
- Verify signature format (64 bytes for Ed25519, 114 for Ed448)

### Iteration 16: DSA/DH

**Target files:** `test_dsa_complete.py`, `test_dh_key_agreement.py`, `wycheproof/test_wycheproof_dsa.py`
**OASIS specs:** `dsa*.md`, `dh*.md`

**Audit scope:**
- Verify DSA parameter generation (L/N pairs per FIPS 186-4)
- Check DH domain parameter handling
- Verify DSA signature format
- Test parameter validation edge cases

## Phase 5: Post-Quantum (Iterations 17-18)

### Iteration 17: ML-KEM & ML-DSA

**Target files:** `test_kem.py`, `test_pqc_sign.py`, `test_mech_kem.py`, `acvp/test_acvp_mlkem.py`, `acvp/test_acvp_mldsa.py`, `wycheproof/test_wycheproof_mlkem.py`, `wycheproof/test_wycheproof_mldsa*.py`
**OASIS specs:** `ml_kem*.md`, `ml_dsa*.md`

**Audit scope:**
- Verify parameter set handling (ML-KEM-512/768/1024, ML-DSA-44/65/87)
- Check `C_EncapsulateKey`/`C_DecapsulateKey` semantics (v3.2)
- Address TODO: `CK_SIGN_ADDITIONAL_CONTEXT` parameter for ML-DSA context
- Cross-ref ACVP vectors for all parameter sets
- Verify shared secret sizes per parameter set

### Iteration 18: SLH-DSA

**Target files:** `test_pqc_sign.py`, `test_hash_slh_dsa.py`, `acvp/test_acvp_slhdsa.py`
**OASIS specs:** `slh_dsa*.md`

**Audit scope:**
- Verify all SLH-DSA parameter sets (SHA2-128s/f, SHA2-192s/f, SHA2-256s/f, SHAKE-128s/f, SHAKE-192s/f, SHAKE-256s/f)
- Check signature size correctness per parameter set
- Verify ACVP vector coverage completeness
- Test hash-then-sign mode

## Phase 6: Key Management & Derivation (Iterations 19-21)

### Iteration 19: Key Lifecycle

**Target files:** `test_keymgmt.py`, `test_key_lifecycle.py`, `test_key_flags.py`, `test_key_sizes.py`, `test_key_usage_policy.py`, `test_sensitivity.py`, `test_handle_reuse.py`
**OASIS specs:** `objects*.md`, `key*.md`

**Audit scope:**
- Verify CKA_EXTRACTABLE/CKA_SENSITIVE transitions per spec (one-way)
- Check CKA_WRAP_WITH_TRUSTED enforcement
- Verify key attribute defaults per spec Table 10
- Test `C_CopyObject` attribute propagation rules
- Check Tookan vulnerability mitigations (CKA_EXTRACTABLE escalation)

### Iteration 20: KDF Operations

**Target files:** `test_kdf.py`, `test_misc_kdf.py`, `test_sp800_108_kdf.py`, `test_hkdf_extended.py`, `test_pbe.py`, `wycheproof/test_wycheproof_hkdf.py`, `wycheproof/test_wycheproof_pbkdf2.py`, `wycheproof/test_wycheproof_pbes2.py`
**OASIS specs:** `kdf*.md`, `hkdf*.md`, `pbkdf2*.md`, `sp800_108*.md`

**Audit scope:**
- Verify HKDF extract/expand parameter handling against RFC 5869
- Check PBKDF2 iteration count enforcement
- Verify SP800-108 KDF modes (counter, feedback, pipeline)
- Add SHA3-based KDF key derivation tests (SHA3_* key derive mechanisms — currently untested)
- Check `CK_SP800_108_KDF_PARAMS` structure correctness

### Iteration 21: Key Wrapping

**Target files:** `test_mech_wrap.py`, `test_authenticated_wrap.py`, `test_rsa_key_wrapping.py`, `acvp/aes/test_wrap.py`
**OASIS specs:** `key_wrapping*.md`, `aes_key_wrap*.md`

**Audit scope:**
- Verify AES-KW semantics (64-bit IV, 8-byte blocks per RFC 3394)
- Verify AES-KWP with padding (RFC 5649)
- Check RSA wrap parameter handling
- Implement v3.2 `C_WrapKeyAuthenticated`/`C_UnwrapKeyAuthenticated` tests if missing
- Verify wrap/unwrap attribute template propagation

## Phase 7: Session/Token/Object (Iterations 22-24)

### Iteration 22: Session Management

**Target files:** `test_session_*.py` (6 files), `test_concurrent_sessions.py`, `test_v30_session.py`, `test_ro_session*.py`
**OASIS specs:** `session*.md`

**Audit scope:**
- Verify state machine transitions against OASIS spec Figure 3 (all 5 states)
- Check R/O session restrictions per spec
- Test session info field correctness
- Verify concurrent session limits and behavior
- Check v3.0 session changes

### Iteration 23: Object Management

**Target files:** `test_object.py`, `test_object_*.py` (4 files), `test_search.py`, `test_data_objects.py`, `test_token_objects.py`, `test_validation_objects.py`, `test_set_attribute.py`, `test_attribute_*.py`
**OASIS specs:** `objects*.md`, `attributes*.md`

**Audit scope:**
- Verify attribute default values against spec per object class
- Check `C_FindObjects` template matching semantics
- Verify session vs token object visibility rules
- Test `C_GetAttributeValue` with `CK_UNAVAILABLE_INFORMATION`
- Check `C_SetAttributeValue` restriction rules per spec

### Iteration 24: Token & PIN Management

**Target files:** `test_pin.py`, `test_so_pin.py`, `test_token_flags.py`, `test_init.py`
**OASIS specs:** `token*.md`, `pin*.md`

**Audit scope:**
- Verify `C_InitToken` behavior per spec (clears all objects except SO PIN)
- Check `C_InitPIN`/`C_SetPIN` parameter validation
- Verify token flags correctness per spec
- Test SO login/operations separation from USER

## Phase 8: Advanced & Protocol (Iterations 25-27)

### Iteration 25: Message-Based API (v3.0+)

**Target files:** `test_message_crypto.py`, `test_mech_message.py`
**OASIS specs:** `message*.md`

**Audit scope:**
- Verify `C_MessageEncryptInit`/`C_EncryptMessage`/`C_EncryptMessageBegin`/`C_EncryptMessageNext` flow
- Same for decrypt, sign, verify message operations
- Check multi-message session semantics
- Verify message operation and single-part operation interaction
- Add comprehensive tests if coverage thin

### Iteration 26: Protocol Operations

**Target files:** `test_tls12.py`, `test_ssl3.py`, `test_wtls.py`, `test_ike.py`, `test_x942_dh.py`, `test_x3dh.py`, `test_double_ratchet.py`
**OASIS specs:** `tls*.md`, `ssl3*.md`, `wtls*.md`

**Audit scope:**
- Fix hardcoded `0x69` in `test_tls12.py` — replace with symbolic constant
- Verify TLS 1.2 PRF parameter structure against spec
- Check SSL3 key material derivation parameters
- Verify IKE mechanism parameter handling
- Cross-ref X3DH and Double Ratchet implementations against Signal spec

### Iteration 27: Async & Operation State

**Target files:** `test_operation_state.py`, `test_remaining_gaps.py` (async TODO)
**OASIS specs:** `async*.md`, `operation_state*.md`

**Audit scope:**
- Implement async lifecycle test (currently TODO in `test_remaining_gaps.py:409`)
- Verify `C_GetOperationState`/`C_SetOperationState` for digest, encrypt, sign operations
- Test operation state portability across sessions
- Check v3.0+ `C_SessionCancel` behavior

## Phase 9: Security & Compliance (Iterations 28-30)

### Iteration 28: Security Audit

**Target files:** `test_padding_oracle.py`, `test_nonce_quality.py`, `test_tookan.py`, `test_api_security.py`, `test_fuzz.py`, `test_attribute_fuzz.py`, `test_mechanism_fuzz.py`, `test_cve_regression.py`

**Audit scope:**
- Verify padding oracle test methodology
- Check nonce randomness statistical tests adequacy
- Cross-ref Tookan attack vectors against paper
- Verify CVE regression tests cover all documented CVEs in `docs/cve-regression.md`
- Add missing security-sensitive negative tests
- Check for timing side-channel test opportunities

### Iteration 29: CKR Compliance

**Target files:** All 30 files in `testcases/ckr/`
**OASIS specs:** Section 5 (return values), mechanism-specific error tables

**Audit scope:**
- Cross-ref every expected CKR return code against OASIS spec
- Verify error priority ordering per spec (e.g., `CKR_SESSION_HANDLE_INVALID` before `CKR_ARGUMENTS_BAD`)
- Check `_ckr_spec.py` specification data correctness
- Verify all CKR codes from `types_std.py` have test coverage
- Fix any incorrect CKR expectations

### Iteration 30: Consolidation

**Actions:**
- Generate master index `docs/audit/00-index.md` linking all iteration reports
- Aggregate statistics: findings count, fixes applied, new tests written, remaining items
- Cross-module consistency check: ensure patterns are consistent across all test files
- Generate coverage delta: mechanisms/functions covered before vs after audit
- List items deferred for future iterations

## Ralph-Loop Configuration

- **Interval:** Per-iteration (not time-based) — each iteration is one ralph-loop cycle
- **Stop condition:** All 30 iterations complete, or user cancels
- **Commit strategy:** One commit per iteration with message format: `audit(NN): component-name — summary of changes`
- **Error handling:** If an iteration encounters a blocker, document it in the report and move to next iteration

## Pre-Audit Checklist

Before starting the ralph-loop:
1. Ensure `dev` branch is clean (no uncommitted changes)
2. Create `docs/audit/` directory
3. Verify OASIS spec files accessible at `/home/user/src/m/pkcs11-check-ws/pkcs11/working/doc/spec/`
4. Verify test data available (`uv run pkcs11-check fetch-data --status`)
