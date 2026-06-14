# PKCS#11 Security Test Additions - Action Plan

**Generated from:** `pkcs11-hardening-test-gap-notes-2026-06-08.md`
**Date:** 2026-06-08 (verified 2026-06-08; see "Verification Pass" below)
**Purpose:** Structured action plan for implementing hardening tests

## Executive Summary

This document organizes the comprehensive hardening gap analysis into actionable test additions. Tests are grouped by priority (Critical/High/Medium/Low) and implementation complexity (Low/Medium/High).

**Target scope (provider-neutral):** every test must be useful against any
PKCS#11 module that advertises the relevant mechanism, interface version, object
class, or operation. Validation runs across the project's full Docker test
matrix — pure-software tokens, FIPS-mode variants, post-quantum-capable software
modules, embedded/TEE modules, TPM-backed modules, and mock modules — but the
tests carry **no provider names, version pins, allowlists, or known-bug masks**.

---

## Verification Pass (2026-06-08)

A source-grounded review cross-checked this plan's coverage claims against the
actual test bodies (parallel file sweeps + direct reads, cross-referenced with
git history). Outcome:

- **Claims are overwhelmingly accurate.** Almost every "Initial Coverage Added"
  / "already has coverage" line maps to a real test with a genuine effect check
  — real guard-byte sentinel comparisons, `classify_*` helpers, and subprocess
  isolation — not a return-code-only probe. Spot examples confirmed by
  file:line: scalar-length (`ckr/test_ckr_object.py`, `ckr/test_ckr_keygen.py`),
  array-pointer (`ckr/test_ckr_object.py`), buffer/state + guard bytes
  (`ckr/test_ckr_raw_buffer.py`), recover lengths
  (`security/test_recover_length_boundary.py`), message lengths + random/seed +
  KDF/PBE/TLS/SP800-108 (`security/test_ffi_length_boundary.py`), DH truncation
  (`test_dh_key_agreement.py`), nested-template enforcement
  (`test_remaining_gaps.py`), GCM ivGenerator guard (`test_mech_message.py`),
  null-arg encrypt/decrypt lifecycle (`test_operation_termination.py:490`).

- **One finding-hiding code bug found and fixed.**
  `test_kem.py::TestMLKEMNegative::test_encapsulate_missing_permission_flag` used
  a catch-all `assert rv in (CKR_OK, CKR_KEY_FUNCTION_NOT_PERMITTED,
  CKR_BUFFER_TOO_SMALL)` — silently tolerating `CKR_OK` — and only ran a
  `pCiphertext=NULL` size query, so a module that ignores `CKA_ENCAPSULATE=False`
  could pass. It now mirrors the decapsulate test: it drives the **full**
  encapsulation (generous output buffer, so a non-conformant size query cannot
  mask the result) and classifies 3-way (`classify_negative_rv` on reject,
  policy `classify_policy_enforcement` on full success). Verified on the Docker
  matrix: a module that enforces the flag passes; a module that does not now
  **fails as a policy finding** instead of passing silently.

- **Doc/file-map corrections** applied to the File Existence Audit, Priority
  Matrix counts, and Files-To-Create list (three "new files" already exist under
  different paths). See those sections.

- **Genuinely outstanding work** (the real remaining plan): public-session
  private-object *creation* rejection; destructive token/SO-PIN policy on
  disposable tokens; subprocess-isolated thread/lifetime stress; optional
  provider-state fuzz harness; plus breadth expansions (remaining nested
  mechanism-params, more nested-template families, KDF output-effect checks).

---

## CRITICAL PRIORITY - Immediate Implementation

### 1. Secret-Key CKA_VALUE_LEN Over-Capacity Tests

**Bug Class:** Module records caller-controlled length before validation, uses it during cleanup/copy/derive/unwrap/zeroization.

**Test Locations:** `testcases/security/test_secret_key_value_len.py`

| API Entry Point | Test Scenario | Expected Outcome | Complexity |
|----------------|---------------|------------------|------------|
| `C_CreateObject` | `CKO_SECRET_KEY` with `CKK_GENERIC_SECRET` and `CKK_AES`, oversized `CKA_VALUE_LEN` (± `CKA_VALUE`) | `CKR_ATTRIBUTE_VALUE_INVALID`, `CKR_KEY_SIZE_RANGE`, `CKR_TEMPLATE_INCONSISTENT`, or `CKR_TEMPLATE_INCOMPLETE` | Low |
| `C_GenerateKey` | Variable-length secret key mechanisms, `CKA_VALUE_LEN=CK_ULONG_MAX` | Clean rejection or genuine success for supported size | Medium |
| `C_DeriveKey` | HKDF and other KDFs with caller templates containing oversized `CKA_VALUE_LEN` | Clean rejection | Medium |
| `C_UnwrapKey` | Output templates with oversized `CKA_VALUE_LEN` | Clean rejection | Medium |
| `C_SetAttributeValue` | Existing secret keys where provider accepts that attribute | Clean rejection or genuine success | Low |

**Positive Controls Required:**
- In-range negative controls for each entry point
- Post-success effect checks for object-creating/mutating paths
- `C_GenerateKey` with `CKM_GENERIC_SECRET_KEY_GEN`: verify normal 32-byte, read back `CKA_VALUE_LEN`, then probe `CK_ULONG_MAX`

**Remaining Expansion:**
- Additional variable-length `C_GenerateKey` mechanisms beyond generic-secret and PBKDF2
- Additional advertised KDFs beyond HKDF with nested mechanism parameters
- In-range positive controls for unwrap and derive families

---

### 2. Operation Initialization Key Type/Usage Validation

**Bug Class:** Operation init doesn't validate key type/usage before storing active operation state.

**Test Location:** `testcases/ckr/test_ckr_wrong_key_type_hardening.py` (exists — 211 lines, crash-safe wrong-key-type init + continuation). Status: **implemented**; remaining value is less-common operations.

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| `C_SignInit(CKM_ECDSA, RSA private key)` + `C_Sign` | Clean rejection at Init or Sign, crash/failure | Medium |
| `C_VerifyInit(CKM_ECDSA, RSA public key)` + `C_Verify` | Clean rejection at Init or Verify, crash/failure | Medium |
| Additional operations with wrong key types | Clean rejection | Medium |

**Implementation Notes:**
- Use crash-safe child process for init + follow-up operation
- Continue into operation if init incorrectly returns `CKR_OK`
- Remaining value: less-common operations and follow-up valid-operation probes

---

### 3. Mechanism Parameter Serializer/Decoder Validation

**Bug Class:** Mechanism parameter serializers/decoders lack length and pointer cross-checks.

**Test Location:** `testcases/security/test_ffi_length_boundary.py` (exists — covers AES-CBC encrypt-data, PBKDF2, PBE, TLS-KDF, SP800-108). Status: **largely implemented**; extend with the remaining mechanisms below (RSA-PSS/OAEP, AES-GCM/CCM, EdDSA).

| Mechanism | Test Scenario | Expected Outcome | Complexity |
|-----------|---------------|------------------|------------|
| RSA-PSS | Malformed parameter lengths | Clean rejection | Medium |
| RSA-OAEP | Nested pData/length pairs | Clean rejection | Medium |
| AES-GCM | Invalid IV/tag lengths | Clean rejection | Medium |
| AES-CBC encrypt-data | Malformed nested pData/length pairs via `C_DeriveKey` | Clean rejection | Medium |
| EdDSA | Invalid parameter structures | Clean rejection | Medium |
| TLS KDFs | Malformed random data lengths | Clean rejection | High |
| PBE | Oversized iteration counts | Clean rejection | Medium |
| HKDF | Invalid parameter lengths | Clean rejection | Medium |
| ECDH-AESKW | Malformed public key encodings | Clean rejection | Medium |
| RSA-AES key wrap | Invalid parameter structures | Clean rejection | High |
| v3.2 KEM/PQC | Invalid parameter set IDs | Clean rejection | High |

**Implementation Notes:**
- Initial AES-CBC encrypt-data derive coverage exists
- Continue through public `C_DeriveKey` API for nested parameter tests

---

### 4. Data Length Truncation Beyond One-Shot Operations

**Bug Class:** Module casts `CK_ULONG` data lengths to narrower signed/unsigned types, reads/writes/hashes wrong amount of memory.

**Test Location:** `testcases/security/test_ffi_length_boundary.py` (extend)

| API Entry Point | Test Scenario | Expected Outcome | Complexity |
|-----------------|---------------|------------------|------------|
| `C_Verify` | Small real data buffer + huge `ulDataLen` | Clean rejection | Low |
| `C_DigestUpdate` | Small real buffer + huge `ulDataLen` | Clean rejection | Low |
| `C_SignUpdate` | Small real buffer + huge `ulDataLen` | Clean rejection | Low |
| `C_VerifyUpdate` | Small real buffer + huge `ulDataLen` | Clean rejection | Low |
| `C_DigestKey` | Imported key with real 16-byte `CKA_VALUE` + oversized `CKA_VALUE_LEN` | Clean rejection or correct digest | Medium |
| `C_SignRecover` | Tiny real data + huge `ulDataLen` | Clean rejection | Medium |
| `C_VerifyRecover` | Tiny signature + huge `ulSignatureLen` + 1-byte output buffer | Clean rejection | Medium |
| `C_EncryptMessage` | Tiny real buffers + huge `ulAssociatedDataLen` or `ulPlaintextLen` | Clean rejection | Medium |
| `C_DecryptMessage` | Tiny real buffers + huge `ulAssociatedDataLen` or `ulCiphertextLen` | Clean rejection | Medium |
| `C_SignMessage` | Tiny real data + huge `ulDataLen` | Clean rejection | Medium |
| `C_VerifyMessage` | Real signature + huge `ulDataLen` or `ulSignatureLen` | Clean rejection | Medium |

**Initial Coverage Added:**
- HMAC `C_Verify`, AES-ECB encrypt/decrypt update, HMAC sign/verify update, SHA-256 digest update
- `C_DigestKey` with temporary generic-secret key
- `C_SignRecover`, `C_VerifyRecover` with RSA keys
- v3.2 message APIs (Encrypt/Decrypt/Sign/Verify Message + Begin/Next)

**Implementation Notes:**
- Use both `0x7fff_ffff_ffff_ffff` and `0x8000_0000_0000_0000` class values
- Prefer exact effect checks over "no crash": output lengths, guard bytes, object visibility
- Subprocess isolation for crash safety

---

### 5. Scalar Attribute Length Validation

**Bug Class:** Module accepts boolean/integer attribute with `ulValueLen` not matching PKCS#11 scalar type, reads wrong amount of caller memory.

**Test Locations:** `testcases/ckr/test_ckr_object.py`, mechanism-specific CKR tests

| API Entry Point | Test Scenario | Expected Outcome | Complexity |
|-----------------|---------------|------------------|------------|
| `C_CreateObject` | Data object with `CK_ULONG`-sized `CKA_TOKEN` value | Template rejection passes, `CKR_OK` fails after destroy | Low |
| `C_CopyObject` | Existing session object with `CK_ULONG`-sized `CKA_TOKEN` | Template rejection passes, `CKR_OK` fails after destroy | Low |
| `C_UnwrapKey` | Valid AES key-wrap + `CK_ULONG`-sized `CKA_TOKEN` in output template | Template rejection passes, `CKR_OK` fails after destroy | Medium |
| `C_GenerateKey` | Advertised AES mechanism + `CK_ULONG`-sized `CKA_TOKEN` in template | Template rejection passes, `CKR_OK` fails after destroy | Low |
| `C_GenerateKeyPair` | RSA mechanism + `CK_ULONG`-sized `CKA_TOKEN` in public/private templates | Template rejection passes, `CKR_OK` fails after destroy | Medium |
| `C_GenerateKeyPair` | EC mechanism (P-256) + malformed `CKA_TOKEN` lengths | Template rejection passes, `CKR_OK` fails after destroy | Medium |
| `C_CreateObject` | Data object with undersized/oversized `CKA_CLASS` storage | Template rejection passes, `CKR_OK` fails after destroy | Low |
| `C_CreateObject` | AES secret key with undersized/oversized `CKA_KEY_TYPE` storage | Template rejection passes, `CKR_OK` fails after destroy | Low |
| `C_GenerateKeyPair` | ML-KEM/ML-DSA + malformed `CKA_PARAMETER_SET` lengths | Template rejection passes, `CKR_OK` fails after destroy | High |
| `C_GenerateKey` | AES mechanism + undersized/oversized `CKA_VALUE_LEN` storage | Template rejection passes, `CKR_OK` fails after destroy | Low |

**Initial Coverage Added:**
- All scenarios listed above already have coverage

**Remaining Expansion:**
- Additional `C_GenerateKeyPair` mechanisms with malformed boolean lengths (EdDSA, PQC)
- Additional `C_UnwrapKey` variants that avoid earlier class/key-type template rejection
- Integer-valued scalar attributes with undersized/oversized lengths beyond initial coverage

**Expected Outcome:** Clean attribute/template rejection. Accepting malformed scalar as valid = hard failure.

---

## HIGH PRIORITY - Next Sprint

### 6. Attribute Array Pointer Validation

**Bug Class:** Module accepts array-valued template attribute with `pValue=NULL_PTR` and `ulValueLen` nonzero, treats as valid or dereferences during parse/persist.

**Test Locations:** `testcases/ckr/test_ckr_object.py`, mechanism-specific CKR tests

| API Entry Point | Test Scenario | Expected Outcome | Complexity |
|-----------------|---------------|------------------|------------|
| `C_CreateObject` | AES secret key with `CKA_ALLOWED_MECHANISMS`: `pValue=NULL_PTR`, `ulValueLen=sizeof(CK_ULONG)` | Clean template/argument rejection | Medium |
| `C_CreateObject` | AES secret key with `CKA_ALLOWED_MECHANISMS`: `pValue=NULL_PTR`, `ulValueLen=0` (empty array) | Clean rejection OR verify empty array is enforced | Medium |

**Initial Coverage Added:**
- Both scenarios listed above already have coverage

**Remaining Expansion:**
- Additional array-valued attributes in copy, unwrap, derive, v3.2 KEM templates
- Additional zero-length `NULL_PTR` cases where empty arrays are legitimate

**Expected Outcome:** Clean rejection for nonzero length with NULL pointer. Accepting = hard failure.

---

### 7. Buffer/State Management - Size-Query and Undersized Buffers

**Bug Class:** Size-query and undersized-buffer behavior lacks guard-byte checks.

**Test Location:** Extend `testcases/security/test_ffi_length_boundary.py`, `testcases/ckr/test_ckr_raw_buffer.py`

| API Entry Point | Test Scenario | Expected Outcome | Complexity |
|-----------------|---------------|------------------|------------|
| `C_GetAttributeValue` | Variable-size attributes, NULL-buffer size query, 1-byte buffer with guard bytes, retry | Exact size reporting, no overwrite, successful retry | Medium |
| `C_GetSlotList` | Undersized 1-entry output array with guard bytes | Guard preservation, required-count checks | Low |
| `C_GetMechanismList` | Undersized 1-entry output buffer with guard bytes | Guard preservation, required-count checks | Low |
| `C_GetInterfaceList` | Undersized 1-entry output buffer with guard bytes | Guard preservation, required-count checks | Low |
| `C_FindObjects` | 1-handle output array with guard bytes after creating 2 matching objects | No extra handles written, count ≤ max | Low |
| `C_GetOperationState` | Undersized 1-byte state buffer after active digest update | Guard preservation, two-call length comparison, retry after `CKR_BUFFER_TOO_SMALL` | Medium |
| `C_WrapKey` | Undersized 1-byte output buffer with guard bytes, two-call retry | Guard preservation, successful retry after `CKR_BUFFER_TOO_SMALL` | Medium |
| `C_WrapKey` (ECDH-AESKW) | Compressed P-256 public key, 1-byte output buffer with guard bytes | Guard preservation, required-length reporting, retry | Medium |
| `C_Decrypt` (AES-CBC-PAD) | Valid ciphertext, 1-byte output buffer, retry without reinit | Guard preservation, exact plaintext on retry | Medium |
| `C_DecryptUpdate` (AES-CBC-PAD) | 1-byte output buffer with guard bytes, retry, final verification | Guard preservation, exact plaintext after final | Medium |
| `C_EncryptFinal` (AES-CBC-PAD) | 1-byte final output buffer with guard bytes after valid update | Guard preservation, retry/state behavior | Medium |
| `C_DecryptFinal` (AES-CBC-PAD) | 1-byte final output buffer with guard bytes after valid update | Guard preservation, retry/state behavior | Medium |
| `C_Digest` (SHA-256) | Undersized output buffer with guard bytes, retry after `CKR_BUFFER_TOO_SMALL` | Guard preservation, correct digest on retry | Low |
| `C_Sign` (RSA-2048) | Undersized output buffer with guard bytes, retry after `CKR_BUFFER_TOO_SMALL` | Guard preservation, successful completion | Medium |

**Initial Coverage Added:**
- All scenarios listed above already have coverage

**Implementation Notes:**
- For `C_GetAttributeValue`: on undersized non-NULL call, `ulValueLen` should become `CK_UNAVAILABLE_INFORMATION`
- For AES-CBC-PAD decrypt: first returned length accepted if large enough to retry and ≤ ciphertext
- Retry must return exact original plaintext

---

### 8. Access-Control and Object-Policy State Machine Invariants

**Bug Class:** Access-control attributes not enforced as state-machine invariants.

**Test Locations:** Existing access-control, attribute-enforcement, RO-session, KEM, CKR KEM tests

| Attribute | Test Scenario | Expected Outcome | Complexity |
|-----------|---------------|------------------|------------|
| `CKA_DERIVE` | `CKA_DERIVE=False` must prevent `C_DeriveKey` | Clean rejection | Low |
| `CKA_ENCAPSULATE` | `CKA_ENCAPSULATE=False` must prevent v3.2 KEM encapsulate | Clean rejection | Medium |
| `CKA_DECAPSULATE` | `CKA_DECAPSULATE=False` must prevent v3.2 KEM decapsulate | Clean rejection | Medium |
| `CKA_COPYABLE` | `CKA_COPYABLE=False` must prevent copying | Clean rejection | Medium |
| `CKA_DESTROYABLE` | `CKA_DESTROYABLE=False` must prevent destruction | Clean rejection | Low |
| Public session | No login, must not create private token/session objects (KEM/unwrap/derive/copy/create) | Clean rejection | Medium |
| `CKA_ALWAYS_SENSITIVE` | Claim must be honored | policy self-contradiction if violated | Medium |
| `CKA_NEVER_EXTRACTABLE` | Claim must be honored | policy self-contradiction if violated | Medium |
| `CKA_PRIVATE` | Public session must not create private objects | Clean rejection | Low |
| `CKA_ALLOWED_MECHANISMS` | Empty array must not allow mechanism use | policy self-contradiction if violated | Medium |
| `CKA_WRAP_WITH_TRUSTED` | Transition rules must be enforced | policy self-contradiction if violated | High |

**Initial Coverage Added:**
- `CKA_ALLOWED_MECHANISMS` empty array coverage
- `CKA_DERIVE`, `CKA_ENCAPSULATE`, `CKA_DECAPSULATE`, `CKA_COPYABLE`, `CKA_DESTROYABLE`, public session object creation

**Expected Outcome:** Clean access-control rejection. Creating/using object after claiming operation prohibited = policy self-contradiction, must fail (not xfail).

---

### 9. Nested Template Constraint Enforcement

**Bug Class:** Module accepts and reports constraint attribute (WRAP/UNWRAP/DERIVE_TEMPLATE) but doesn't enforce it.

**Test Location:** Extend `testcases/test_remaining_gaps.py` or dedicated `testcases/security/test_nested_template_enforcement.py`

| Constraint Attribute | Test Scenario | Expected Outcome | Complexity |
|---------------------|---------------|------------------|------------|
| `CKA_WRAP_TEMPLATE` | Generate wrapping key with nested `CKA_LABEL` constraint, verify matching target works, then try wrapping target with different label | policy self-contradiction if violation accepted | High |
| `CKA_UNWRAP_TEMPLATE` | Wrap real AES key, unwrap once with matching output template, then unwrap same blob with violating `CKA_LABEL` | policy self-contradiction if violation accepted | High |
| `CKA_DERIVE_TEMPLATE` | Import derivable key with nested label constraint, derive once with matching template, then derive with violating label | policy self-contradiction if violation accepted | High |

**Initial Coverage Added:**
- All three scenarios listed above already have coverage

**Remaining Expansion:**
- More mechanism families: RSA/OAEP unwrap, ECDH/HKDF derive, v3.2 KEM encapsulate/decapsulate templates
- Additional nested constraints beyond `CKA_LABEL`: key type, operation permissions, sensitivity/extractability, allowed mechanisms

**Expected Outcome:** If module reports template attribute and still accepts violating target, policy self-contradiction failure.

---

### 10. Operation-State Cleanup After Errors

**Bug Class:** Early error leaves session in stale active state, blocks next `*Init`, causes wrong results, terminates wrong operation.

**Test Locations:** `testcases/test_operation_termination.py`, `testcases/test_operation_state.py`, CKR raw multipart/state tests

| API Entry Point | Test Scenario | Expected Outcome | Complexity |
|-----------------|---------------|------------------|------------|
| `C_DigestUpdate` | Cleanly rejected invalid input, then verify fresh init works | Spec-correct active/terminated state | Medium |
| `C_SignUpdate` | Cleanly rejected invalid input, then verify fresh init works | Spec-correct active/terminated state | Medium |
| `C_VerifyUpdate` | Cleanly rejected invalid input, then verify fresh init works | Spec-correct active/terminated state | Medium |
| `C_DigestKey` | Cleanly rejected invalid input, then verify fresh init works | Spec-correct active/terminated state | Medium |
| Multipart decrypt | Buffer-too-small or invalid length paths, verify state | Spec-correct active/terminated state | Medium |
| Multipart verify | Finalization after buffer-too-small or invalid length paths | Spec-correct active/terminated state | Medium |
| Reinitialize | Same operation after error, verify second valid operation works | Spec-correct active/terminated state | Medium |

**Implementation Notes:**
- Separate three cases:
  1. Functions that always terminate operation after terminal call, even on rejection
  2. Functions that preserve operation after `CKR_BUFFER_TOO_SMALL` (retry required)
  3. Functions where invalid input should terminate (stale operation = cascade failure)
- Explicitly record which rule applies, then probe next `*Init`/retry/finalizer

**Expected Outcome:** Spec-correct active/terminated state. Wrong state after claimed successful/recoverable error = lifecycle self-contradiction.

---

### 11. Generated Output Parameter Guarding

**Bug Class:** Mechanisms write generated IVs/nonce/tags/contexts/key material back to mechanism-parameter structs; functional tests pass but output overwrite or size-reporting issues exist.

**Test Location:** Existing generated-output and authenticated-wrap/message tests with raw guard-byte helpers

| Mechanism | Test Scenario | Expected Outcome | Complexity |
|-----------|---------------|------------------|------------|
| `C_EncryptMessage` (AES-GCM) | `CK_GCM_MESSAGE_PARAMS.ivGenerator` with guarded caller buffers for generated IV/tag outputs, then decrypt result with independent AES-GCM implementation | No output overwrite beyond `ulIvLen`/`ulTagBits`, correct decryption | High |

**Initial Coverage Added:**
- `C_EncryptMessage` with AES-GCM already has coverage

**Implementation Notes:**
- Generated IV/nonce/tag paths: small declared buffers surrounded by guard bytes
- Mechanism structs with output pointer set but output length too small: clean error or exact required size
- Generated outputs must be nonzero/non-default when `CKR_OK` claims module generated them
- Positive control with correctly sized output buffers

---

## MEDIUM PRIORITY - Future Sprints

### 12. Template Count Overflow on Valid Handles

**Bug Class:** Module multiplies `ulCount * sizeof(CK_ATTRIBUTE)` or iterates caller-supplied count without rejecting impossible values.

**Test Location:** `testcases/security/test_arithmetic_overflow.py`

| API Entry Point | Test Scenario | Expected Outcome | Complexity |
|-----------------|---------------|------------------|------------|
| `C_GetAttributeValue` | Temporary session `CKO_DATA` object + impossible template count | Clean rejection | Low |
| `C_SetAttributeValue` | Temporary session `CKO_DATA` object + impossible template count | Clean rejection | Low |
| `C_CopyObject` | Existing session object + impossible template count | Clean rejection | Low |
| `C_DeriveKey` | Valid base key (`CKM_CONCATENATE_BASE_AND_DATA`) + impossible output-template count | Clean rejection | Medium |
| `C_EncapsulateKey` (v3.2) | Real ML-KEM keypair + one real output-template attribute + impossible output-template count | Clean rejection | Medium |
| `C_DecapsulateKey` (v3.2) | Real ML-KEM keypair + one real output-template attribute + impossible output-template count | Clean rejection | Medium |

**Initial Coverage Added:**
- All scenarios listed above already have coverage

**Remaining Expansion:**
- Continue replacing handle-zero probes with real handles where target API would otherwise reject before reaching template processing

**Expected Outcome:** Clean argument/template rejection. Crash/timeout/huge allocation = hard failure.

---

### 13. Misaligned Caller Pointers (FFI Robustness)

**Bug Class:** Module casts caller-provided `void *` or struct pointers directly to scalar types, crashes or reads wrong value when FFI caller supplies valid byte buffer at unaligned address.

**Test Location:** `testcases/security/test_ffi_alignment.py`

| API Entry Point | Test Scenario | Expected Outcome | Complexity |
|-----------------|---------------|------------------|------------|
| `C_GenerateKey` | AES key template with scalar attribute `pValue` pointers intentionally shifted by 1 byte | Success AND clean rejection both acceptable; crash/abort/timeout/child-script failure NOT acceptable | Medium |
| `C_EncryptInit` | Valid AES-ECB mechanism struct stored at intentionally unaligned address | Success AND clean rejection both acceptable; crash/abort/timeout/child-script failure NOT acceptable | Medium |

**Initial Coverage Added:**
- Both scenarios listed above already have coverage

**Remaining Expansion:**
- Mechanism-parameter structs with nested pointers: RSA-OAEP/PSS, AES-GCM/CCM, HKDF, TLS KDF, v3.2 KEM/PQC parameter structs

**Expected Outcome:** No crash or forced process exit. This is robustness probe, not strict conformance verdict. `CKR_OK` acceptable if operation state remains coherent; clean rejection also acceptable.

---

### 14. KDF and PBE Length/Parameter Validation

**Bug Class:** KDF/PBE mechanisms lack proper parameter validation and length checks.

**Test Location:** `testcases/security/test_ffi_length_boundary.py` (extend), borrowing setup from existing TLS/PBE/PBKDF2/KDF tests

| Mechanism | Test Scenario | Expected Outcome | Complexity |
|-----------|---------------|------------------|------------|
| `C_DeriveKey` (DH) | Verify exact requested `CKA_VALUE_LEN` for extractable generic-secret outputs, check 32-byte vs 16-byte left-truncation relationship | Exact requested length, spec-correct truncation/padding | Medium |
| `C_GenerateKey` (PBKDF2) | `pPassword`, `pSaltSourceData`, `pPrfData` with tiny real buffers + claimed `isize::MAX` and `isize::MAX + 1` lengths | `CKR_MECHANISM_PARAM_INVALID`, `CKR_ARGUMENTS_BAD`, `CKR_DATA_LEN_RANGE`, or similar | High |
| `C_GenerateKey` (PBKDF2) | Requested output size through `CKA_VALUE_LEN=CK_ULONG_MAX` | Clean rejection, subprocess crash isolation | Medium |
| `C_GenerateKey` (PKCS#12 PBE/PBA) | `CK_PBE_PARAMS.pPassword` and `pSalt` with tiny real buffers + claimed `isize::MAX` and `isize::MAX + 1` lengths | Clean rejection | Medium |
| `C_DeriveKey` (TLS KDF) | `CK_SSL3_RANDOM_DATA.pClientRandom` and `pServerRandom` with tiny real buffers + claimed `isize::MAX` and `isize::MAX + 1` lengths | Clean rejection | High |
| `C_DeriveKey` (SP800-108) | Real `pDataParams` array with huge `ulNumberOfDataParams` | Clean rejection | Medium |
| `C_DeriveKey` (SP800-108) | Real one-entry `pAdditionalDerivedKeys` array with huge `ulAdditionalDerivedKeys` count | Clean rejection | Medium |

**Initial Coverage Added:**
- All scenarios listed above already have coverage

**Remaining Expansion:**
- PBKDF2 iteration-count boundaries
- Additional PKCS#12 PBE mechanisms beyond functional PBE coverage set
- TLS 1.2 master-key/key-material derive structures (version, returned-key-material output buffers)
- Additional KDFs with nested pointer arrays and additional-output templates

**Expected Outcome:** Clean `CKR_MECHANISM_PARAM_INVALID`, `CKR_ARGUMENTS_BAD`, `CKR_DATA_LEN_RANGE`, or similar. Crash/hang/excessive allocation/success with nonsensical lengths = failure.

---

### 15. Nested KDF Array and Additional-Key Counts

**Bug Class:** KDF parameter structs contain arrays or secondary output templates separate from simple pointer+length bugs.

**Test Location:** `testcases/security/test_ffi_length_boundary.py` plus KDF-specific functional tests

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| KDF count fields for arrays of nested data parameters (initial SP800-108 coverage) | Clean rejection for huge counts | Medium |
| Additional-derived-key arrays (initial SP800-108 coverage) | Clean rejection for huge additional-key count | Medium |
| Returned key-material structs with undersized or NULL output buffers | Clean error or exact required size | High |
| Derived-key templates in primary and additional outputs | Same template-count and `CKA_VALUE_LEN` hardening as direct `C_DeriveKey` | High |

**Initial Coverage Added:**
- SP800-108 nested data params array and additional-derived-keys array coverage

**Remaining Expansion:**
- Extend same pattern to other KDF structs as they become practical
- Returned key-material structures or secondary outputs

---

### 16. Other Caller-Controlled Length Surfaces

**Bug Class:** Truncation and oversized-copy mistakes in various public API families.

**Test Locations:** Extend `testcases/security/test_ffi_length_boundary.py` for crypto/random/PIN lengths; extend CKR raw/list tests for output-list sizing

| API Family | Test Scenario | Expected Outcome | Complexity |
|------------|---------------|------------------|------------|
| `C_WrapKey` output length | Two-call size query, undersized output buffer, guard-byte checks | `CKR_BUFFER_TOO_SMALL` with correct required length | Medium |
| `C_UnwrapKey` wrapped-key input length | Validate input length handling | Clean rejection or successful unwrap | Medium |
| `C_GenerateRandom` output length | Extreme claimed-length probes with tiny real caller allocations | No crash/forced exit/oversized write into guard bytes | Low |
| `C_SeedRandom` seed length | Extreme claimed-length probes with tiny real caller allocations | No crash/forced exit/oversized write into guard bytes | Low |
| PIN lengths (`C_Login`, `C_InitPIN`, `C_SetPIN`, `C_InitToken`) | Destructive/disposable-token gated | Clean rejection | High |
| Username lengths | Destructive/disposable-token gated | Clean rejection | High |
| Token label lengths | Destructive/disposable-token gated | Clean rejection | High |

**Initial Coverage Added:**
- `C_WrapKey` undersized output buffers with guard bytes, two-call retry
- `C_GenerateRandom` and `C_SeedRandom` extreme claimed-length probes
- `C_GetSlotList`, `C_GetMechanismList`, `C_GetInterfaceList`, `C_FindObjects`, `C_GetOperationState` undersized buffers

**Remaining Expansion:**
- Destructive/disposable-token coverage for PIN/SO-PIN/token-label/username length surfaces
- Follow-up retry/state-preservation checks after `CKR_BUFFER_TOO_SMALL` for remaining byte-output APIs

---

## LOW PRIORITY - Infrastructure/Experimental

### 17. Thread and Lifetime Stress Tests

**Bug Class:** Session, login, and operation lifetime bugs show up as stale locks, leaked active operations, double-close behavior, inconsistent login state under concurrency.

**Test Location:** Dedicated stress file or extension of existing session/thread tests, with marker to keep out of fast default runs

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| Object search while another thread creates/destroys matching session objects | No crash/hang/double-free/use-after-free/corrupted later session state | High |
| Two threads racing `C_CloseSession` on same handle | No crash/hang/double-free/use-after-free | High |
| One thread opening/closing sessions while another calls `C_CloseAllSessions` | No crash/hang/double-free/use-after-free | High |
| Concurrent `C_Initialize`, simple read-only calls, `C_Finalize` using valid locking flags | No crash/hang/double-free/use-after-free | High |

**Implementation Notes:**
- Non-default stress tests, run in subprocesses with bounded loops and timeouts
- Use spec-valid locking mode or application mutex callbacks
- Treat "both calls returned `CKR_OK` when only one operation could win" as state-machine failure
- Keep token-mutating stress probes off shared persistent tokens
- Prefer several small deterministic race probes over one broad soak test

**Expected Outcome:** No crash, hang, double free, use-after-free, or corrupted later session state. Clean stale-handle errors acceptable where race makes handle genuinely stale.

---

### 18. Destructive Token Policy Tests

**Bug Class:** Token initialization and PIN policy enforcement gaps.

**Test Location:** `testcases/test_so_pin.py` or new destructive SO-policy test

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| `C_InitToken` with wrong SO PIN on disposable tokens | Verify same SO failure/lockout policy as advertised for SO login | High |

**Implementation Notes:**
- Disposable tokens only
- Repeatedly call with wrong SO PIN
- Verify lockout policy

**Expected Outcome:** Provider-policy-specific clean lockout or rejection. Unlimited wrong SO PIN attempts through token initialization = security policy finding if token otherwise enforces SO lockout.

---

### 19. Optional Provider-State Fuzz Harness

**Bug Class:** Persistent-token and client/transport serialization bugs not reproducible through pure PKCS#11 calls, but public API can stress decode paths.

**Test Location:** Optional explicit harness, not in normal conformance coverage

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| Create token objects through ordinary PKCS#11 calls | N/A | High |
| Finalize module and corrupt length fields in disposable token store | N/A | High |
| Reinitialize and call APIs that force object decode: `C_FindObjects`, `C_GetAttributeValue`, `C_SignInit`, `C_DeriveKey`, `C_DestroyObject` | Clean load rejection, missing object, or operation-specific CKR | High |

**Implementation Notes:**
- Not normal conformance coverage (mutates provider-owned persisted state outside Cryptoki API)
- Keep optional and explicit
- Requires provider-target metadata describing disposable token store location
- Should not run against user-owned tokens

**Expected Outcome:** Clean load rejection, missing object, or operation-specific CKR. Crash/hang/excessive allocation/heap corruption = finding.

---

### 20. Attribute Mixed-Error Continuation Behavior

**Bug Class:** `C_GetAttributeValue` must continue filling template after benign per-attribute errors per spec.

**Test Location:** Attribute/getattr tests

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| Request sensitive `CKA_VALUE` followed by safe `CKA_LABEL` | Fail if later safe attribute left unfilled after `CKR_ATTRIBUTE_SENSITIVE` | Medium |

**Initial Coverage Added:**
- `C_GetAttributeValue` mixed-attribute continuation already has coverage

**Expected Outcome:** Spec-mandated "continue filling the template" behavior after benign per-attribute errors.

---

### 21. Sensitive Attribute Direct Buffer Protection

**Bug Class:** Return-code-only sensitive-attribute tests incomplete; modules might copy protected bytes even while returning sensitive-attribute rejection.

**Test Location:** Sensitive attribute tests

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| Call `C_GetAttributeValue` directly on known sensitive AES key with real `CKA_VALUE` output buffer | Fail if module copies protected bytes even while returning sensitive-attribute rejection | Medium |

**Initial Coverage Added:**
- Sensitive attribute direct buffer protection already has coverage

**Expected Outcome:** No protected bytes copied even when returning `CKR_ATTRIBUTE_SENSITIVE`.

---

### 22. Digest Key Protected Key Edge Case

**Bug Class:** `CKA_SENSITIVE=True` / `CKA_EXTRACTABLE=False` key material can still be digested internally without exposing `CKA_VALUE`.

**Test Location:** Digest key tests

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| Import known protected AES key, digest it | Accept clean provider-policy rejections as visible xfail; verify exact SHA-256 digest if operation succeeds | Medium |

**Initial Coverage Added:**
- `C_DigestKey` protected key edge case already has coverage

**Expected Outcome:** Internal digest succeeds without exposing `CKA_VALUE`.

---

### 23. Attribute Partial Update Risk

**Bug Class:** `C_SetAttributeValue` partial-update risk when one row succeeds before later row fails.

**Test Location:** SetAttributeValue tests

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| Prove mutable label updates operational, then submit `CKA_LABEL` followed by read-only `CKA_CLASS` in one template | Fail if rejected call leaves new label behind | Medium |

**Initial Coverage Added:**
- `C_SetAttributeValue` partial-update already has coverage

**Expected Outcome:** No partial state left behind after rejection.

---

### 24. Mechanism List Filtering Gap

**Bug Class:** Querying nonsense mechanism ID is not same as querying real standard `CKM_*` value absent from slot's `C_GetMechanismList`.

**Test Location:** Mechanism list tests

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| Pick common absent standard mechanism, query via `C_GetMechanismInfo` | Require `CKR_MECHANISM_INVALID` | Low |

**Initial Coverage Added:**
- Mechanism list filtering gap already has coverage

**Expected Outcome:** `CKR_MECHANISM_INVALID` for absent standard mechanism.

---

### 25. Encrypt/Decrypt Lifecycle State Preservation

**Bug Class:** Invalid argument validation can leave stale operation state behind.

**Test Location:** Operation lifecycle tests

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| Start real AES-CBC encrypt/decrypt operation, call one-shot or update function with NULL input pointer or NULL output-length pointer, then verify rejected operation no longer blocks fresh init | No stale operation state after rejection | Medium |

**Initial Coverage Added:**
- Encrypt/decrypt lifecycle state preservation already has coverage

**Expected Outcome:** Fresh init succeeds after rejection, no stale state.

---

### 26. Wrap Policy Attribute Transition Rules

**Bug Class:** Wrap enforcement alone does not prove `CKA_WRAP_WITH_TRUSTED` transition rules.

**Test Location:** Wrap policy tests

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| Create key with `CKA_WRAP_WITH_TRUSTED=True`, attempt to clear it with `C_SetAttributeValue` | Fail if stricter policy actually removed | Medium |

**Initial Coverage Added:**
- Wrap policy attribute transition rules already have coverage

**Expected Outcome:** Policy attribute transitions properly enforced.

---

### 27. NULL Mechanism Init State Behavior

**Bug Class:** NULL mechanism init probes only checked crash/reject behavior, not state cleanup.

**Test Location:** Operation lifecycle tests

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| Start digest operation, call `C_DigestInit(NULL)`, verify `CKR_OK` not reported without making fresh digest init possible | Fail if `CKR_OK` reported but fresh init impossible | Low |

**Initial Coverage Added:**
- NULL mechanism init state behavior already has coverage

**Expected Outcome:** Either clean rejection OR fresh init possible after rejection.

---

### 28. NULL Template Valid Empty Path

**Bug Class:** NULL-template error probes did not cover valid empty-template path.

**Test Location:** Template tests

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| Try fixed-length secret key generation with `pTemplate=NULL` and `ulCount=0`, verify generated object class and key type after `CKR_OK` | Generated object has correct class/type | Low |

**Initial Coverage Added:**
- NULL template valid empty path already has coverage

**Expected Outcome:** `CKR_OK` with correct object, not treated as error.

---

### 29. Derive Key Handle Validation

**Bug Class:** Existing derive tests covered wrong mechanisms and wrong key types but not literal invalid base-key handle.

**Test Location:** Derive key tests

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| Call `C_DeriveKey` with advertised no-parameter key derivation mechanism, valid output template, and `hBaseKey=0` | Clean handle rejection | Low |

**Initial Coverage Added:**
- Derive key handle validation already has coverage

**Expected Outcome:** Clean `CKR_KEY_HANDLE_INVALID` or similar.

---

### 30. ML-KEM Derive Capability Check

**Bug Class:** Generated ML-KEM private keys should not claim `CKA_DERIVE=True`.

**Test Location:** KEM tests

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| Read `CKA_DERIVE` from generated ML-KEM private key | Fail only if module reports forbidden derive capability | Low |

**Initial Coverage Added:**
- ML-KEM derive capability check already has coverage

**Expected Outcome:** `CKA_DERIVE=False` for ML-KEM private keys.

---

### 31. FindObjects NULL Template Match-All Behavior

**Bug Class:** `C_FindObjectsInit(NULL_PTR, 0)` is empty-template match-all search, not NULL-template error.

**Test Location:** FindObjects tests

| Test Scenario | Expected Outcome | Complexity |
|---------------|------------------|------------|
| Create session object, start search with literal NULL pointer and zero count, verify object returned | Object found in match-all search | Low |

**Initial Coverage Added:**
- FindObjects NULL template match-all behavior already has coverage

**Expected Outcome:** Match-all search succeeds, returns all objects.

---

### 32. Token-Management Length Surfaces

**Bug Class:** Length field validation in token-management APIs.

**Test Location:** Token management tests (destructive/disposable-token gated)

| API Entry Point | Test Scenario | Expected Outcome | Complexity |
|-----------------|---------------|------------------|------------|
| `C_InitToken` | Token label length validation | Clean rejection | High |
| `C_InitPIN` | PIN length validation | Clean rejection | High |
| `C_SetPIN` | PIN length validation | Clean rejection | High |
| `C_Login` | PIN length validation | Clean rejection | High |
| `C_LoginUser` | Username length validation | Clean rejection | High |

**Remaining Expansion:**
- Destructive/disposable-token coverage for all PIN/SO-PIN/token-label/username length surfaces

**Expected Outcome:** Clean rejection for invalid lengths.

---

## IMPLEMENTATION GUIDELINES

### General Principles

1. **Use capability gates, interface-version gates, and existing setup classifiers**
2. **Do NOT use provider allowlists, provider-specific skips, or known-bug masks**
3. **A crash, abort, signal, timeout, heap corruption, wrong successful output, or accepted self-contradictory protection claim is a FINDING**
4. **A clean rejection of an advertised but non-operational path is visible xfail evidence** (unless classification model says accepted behavior is hard self-contradiction)
5. **Run dangerous raw pointer, huge length, and race probes in subprocesses** so one module crash does not stop the rest of the suite
6. **Keep provider-state corruption tests out of default runs** unless token store is disposable and explicitly controlled by target

### Test Design Principles

1. **Use real sessions, real objects, and advertised mechanisms where possible**
2. **Preflight setup in parent process when later child probe needs key generation or object import**
   - Setup rejects should classify as visible setup xfail, not as hard failure in malformed call
3. **Keep malformed raw calls in child processes**
   - Child should report whether target call returned cleanly, crashed, hung, or exited unexpectedly
4. **Prefer exact effect checks over only "no crash"**
   - Output lengths, guard bytes, object visibility, operation state, object attributes after `CKR_OK` determine correctness
5. **Add negative controls with in-range values for new helper families**
   - Otherwise provider that rejects setup for unrelated reasons can make test look stronger than it is
6. **Use destructive/disposable-token gating for PIN, token initialization, token object persistence, lockout, and provider-state corruption probes**

### Classification Model

Every test classifies `pass`/`xfail`/`fail`/`skip` by one provider-general rule:

**Classify by what the module did versus what is correct** — the pivot is direction:

| Verdict | Positive op (valid input, advertised mechanism) | Negative op (must reject invalid input / policy) |
|---------|-------------------------------------------------|--------------------------------------------------|
| **pass** | `CKR_OK` + correct output/value | Rejects with **expected** spec CKR |
| **xfail** | Clean error — advertised but not operational | Rejects with **some other** (clean) code |
| **fail** | `CKR_OK` but **wrong** output/value | `CKR_OK`/accepted **and** crypto-correctness break (crypto) or self-contradiction (policy/lifecycle/metadata) |
| **fail** | Crash / hang | Crash / hang |
| **skip** | Capability genuinely absent | Capability genuinely absent |

**Core principle:** Self-contradiction = `fail`. A single honest deviation = `xfail`.

**Four self-contradiction classes that `fail` on acceptance:**
- **crypto:** Crypto-correctness (wrong/forgeable result)
- **policy:** Attribute/permission (claimed protection then violated it)
- **lifecycle:** Lifecycle/state (claimed success then didn't honor it)
- **metadata:** Derived-attribute invariant (two linked attributes that cannot both be true)

### Helper Functions

- `classify_negative_rv(rv, expected_rvs, *, label, allow_ok=False)` — for negative ops outside table
- `reject_or_classify(exc, expected_rvs, *, label)` — for negative ops outside table
- `classify_policy_enforcement(*, claimed, violated, label)` — for policy
- `classify_lifecycle_effect(*, claimed_success, effect_observed, label)` — for lifecycle
- `assert_ckr()` (3-way) over `CkrExpectation` in `testcases/ckr/_ckr_spec.py` — for table-driven negative sites

### Subprocess Isolation

**Use `run_raw_subprocess` (`testcases/_raw_subprocess.py`) for:**
- Tests that need their OWN child to run controlled crash-expecting sub-script
- Tests that need to assert on a specific crash's `returncode`

**Do NOT use for:**
- General crash survival (already provided by `--isolation auto`)
- Normal tests that might crash (isolation already handles this)

### Expected Outcomes Pattern

| Test Type | Expected Outcome |
|-----------|-----------------|
| Secret-key `CKA_VALUE_LEN` over-capacity | `CKR_ATTRIBUTE_VALUE_INVALID`, `CKR_KEY_SIZE_RANGE`, `CKR_TEMPLATE_INCONSISTENT`, or `CKR_TEMPLATE_INCOMPLETE`; or genuine success |
| Template count overflow | Clean argument/template rejection |
| Scalar attribute length validation | Clean attribute/template rejection |
| Attribute array pointer validation | Clean attribute/template/argument rejection for nonzero length with NULL pointer |
| Data length truncation | Clean length/data rejection |
| Misaligned caller pointers | No crash or forced process exit (robustness probe, not strict conformance) |
| Buffer/state management | Exact size reporting on NULL-buffer query, no overwrite on undersized non-NULL call |
| Access-control enforcement | Clean access-control rejection; violation = policy self-contradiction |
| Nested template enforcement | Clean rejection if template reported; violation = policy self-contradiction |
| Operation-state cleanup | Spec-correct active/terminated state |
| Generated output guarding | No output overwrite beyond declared length, correct operation |
| Thread/lifetime stress | No crash, hang, double free, use-after-free, or corrupted state |
| Destructive token policy | Provider-policy-specific clean lockout or rejection |
| Provider-state fuzz | Clean load rejection, missing object, or operation-specific CKR |

---

## PRIORITY MATRIX

| Priority | Count | Test Areas | Timeline |
|----------|-------|------------|----------|
| **Critical** | 5 | Secret-key VALUE_LEN, Operation init validation, Mechanism params, Data length truncation, Scalar attributes | Sprint 1-2 |
| **High** | 6 | Array pointer validation, Buffer/state management, Access-control, Nested templates, Operation-state cleanup, Generated output guarding | Sprint 3-4 |
| **Medium** | 5 | Template count overflow, Misaligned pointers, KDF/PBE validation, Nested KDF arrays, Other length surfaces | Sprint 5-6 |
| **Low** | 17 | Thread stress, Destructive policy, Provider fuzz, Attribute behavior, Lifecycle edge cases, Mechanism gaps, KEM checks | Sprint 7-8 |

**Total Test Additions:** 33 categories
**Categories implemented and verified (2026-06-08 pass):** the large majority —
including the four originally tracked as "new files" below, which already exist
under different paths (see Verification Pass)
**Categories genuinely outstanding:** a handful — public-session private-object
*creation* rejection, destructive token/SO-PIN policy, subprocess-isolated
thread/lifetime stress, and the optional provider-state fuzz harness; the rest of
the backlog is breadth (more mechanism families per an existing pattern)

---

## FILES TO CREATE OR EXTEND

> Corrected by the 2026-06-08 verification pass. The original "New Test Files"
> list named four files; three already exist under different paths. Prefer
> extending existing files over inventing new names.

### New Test Files (genuinely missing)

1. `testcases/test_destructive_token_policy.py` — disposable-token SO-PIN / PIN /
   label policy (extends the partial coverage in `ckr/test_ckr_destructive.py`
   and `test_so_pin.py`)
2. `testcases/test_provider_state_fuzz.py` (optional, disposable-token gated) —
   provider-state corruption harness (no `fuzz/` directory exists; keep it a
   top-level file alongside `test_fuzz.py`)

### Already exist — extend these instead of creating new files

- `testcases/security/test_secret_key_value_len.py` — secret-key over-capacity (created)
- `testcases/ckr/test_ckr_wrong_key_type_hardening.py` — operation-init key-type/usage validation
- `testcases/security/test_ffi_length_boundary.py` — mechanism-param + data-length + KDF/PBE + other length surfaces
- `testcases/test_remaining_gaps.py::TestTemplateConstraintAttributes` — nested wrap/unwrap/derive template enforcement

### Extend Existing Test Files

1. `testcases/security/test_ffi_length_boundary.py` — Data length truncation, KDF/PBE validation, Other length surfaces, remaining nested mechanism-params (RSA-PSS/OAEP, AES-GCM/CCM, EdDSA)
2. `testcases/security/test_ffi_alignment.py` — Misaligned caller pointers (mechanism-param structs)
3. `testcases/security/test_arithmetic_overflow.py` — Template count overflow (remaining handle-zero → real-handle conversions)
4. `testcases/ckr/test_ckr_object.py` — Scalar attribute length validation, Attribute array pointer validation
5. `testcases/ckr/test_ckr_raw_buffer.py` — Buffer/state management, Generated output guarding
6. `testcases/test_operation_termination.py` / `testcases/test_operation_state.py` — Operation-state cleanup (terminate-vs-preserve)
7. `testcases/test_access_control.py` / `testcases/test_access_levels.py` — public-session private-object CREATION rejection (new invariant)
8. `testcases/test_stress.py` — wrap session/lifetime race probes in subprocess isolation (currently in-process)

---

## VALIDATION AND QUALITY GATES

### Pre-Commit Checks

For each test addition:

1. **Run linting:** `uv run ruff check`
2. **Run type checking:** `uv run mypy --strict`
3. **Run tests:** `uv run pytest` (with appropriate module targets)
4. **Verify classification:** Ensure test uses correct helpers (`classify_negative_rv`, `reject_or_classify`, `classify_policy_enforcement`, `classify_lifecycle_effect`, `assert_ckr`)
5. **Check subprocess isolation:** Dangerous tests must use subprocess isolation
6. **Verify capability gating:** Tests must use capability/interface-version gates

### Module Testing

Test against multiple PKCS#11 implementations:

- **Minimum:** the primary software-token targets in the matrix
- **Comprehensive:** 6+ structurally different modules in the matrix
- **Experimental:** every Docker target where the capability is advertised

---

## DEEP AUDIT FINDINGS (2026-06-08)

### File Existence Audit

**Corrected by the 2026-06-08 verification pass.** Three of the four files this
plan tracked as "missing/new" are actually **already covered under a different
path** — the work landed in existing files, not the names this plan invented. Do
**not** create those files; extend the existing ones. Only one new file is
genuinely needed.

| Status | Item | Reality (verified) |
|---|---|---|
| **Already covered** | (was) `testcases/security/test_operation_init_key_validation.py` | Done as `testcases/ckr/test_ckr_wrong_key_type_hardening.py` (211 lines): crash-safe wrong-key-type init + continuation, e.g. `C_SignInit(CKM_ECDSA, RSA priv)` → `C_Sign` |
| **Largely covered** | (was) `testcases/security/test_mechanism_param_validation.py` | Done in `testcases/security/test_ffi_length_boundary.py` (AES-CBC encrypt-data, PBKDF2, PBE, TLS-KDF, SP800-108). Remaining: RSA-PSS/OAEP, AES-GCM/CCM, EdDSA nested-param probes — extend that file |
| **Covered** | (was) `testcases/security/test_nested_template_enforcement.py` | Done in `testcases/test_remaining_gaps.py::TestTemplateConstraintAttributes` (wrap/unwrap/derive). Split out only if it grows |
| **Genuinely missing** | `testcases/test_destructive_token_policy.py` | Partial coverage in `testcases/ckr/test_ckr_destructive.py` + `testcases/test_so_pin.py`; disposable-token SO-PIN-lockout-via-`C_InitToken` policy test still to add |
| **Dir→File** | `testcases/stress/` | No such dir; coverage is in `test_stress.py` (probes are mostly NOT subprocess-isolated — see plan §17) |
| **Dir→File** | `testcases/fuzz/` | No such dir; coverage is in `test_fuzz.py` (Hypothesis property tests) |

**7 existing files NOT referenced in plan but providing relevant coverage:**

| File | Defs | Relevant Coverage |
|---|---|---|
| `test_access_levels.py` | 36 | Role-based access (CKA_WRAP_WITH_TRUSTED, SO vs USER) |
| `test_session_state_machine.py` | 43 | Session state transitions, stale handle detection |
| `test_object_visibility.py` | 31 | Cross-session object visibility |
| `test_surface_audit.py` | 23 | API surface completeness |
| `test_keypair_consistency.py` | 8 | Keypair attribute consistency |
| `test_always_authenticate.py` | 5 | CKA_ALWAYS_AUTHENTICATE operational enforcement |
| `test_mech_flags.py` | 11 | Mechanism info flag validation |

**Statistics:** 241 product test files, ~2,577 test defs. Security directory: 16 files, ~246 defs.

### Missing API Surfaces (Not Addressed in Original Plan)

These API surfaces are not identified as hardening targets in any of the three documents, but have existing compliance tests that could be extended with crash-safe subprocess probes:

#### S1: C_WaitForSlotEvent Edge Cases — Medium Priority

- **Existing coverage:** `test_remaining_gaps.py` (non-blocking poll), `test_ckr_slot_token.py` (error conditions)
- **Missing crash-safe probes:**
  - Blocking call with NULL slot_id pointer
  - Invalid flags parameter
  - Behavior when slot event occurs during wait
- **Best location:** `testcases/test_remaining_gaps.py`
- **Classification:** Negative ops — expect CKR_ARGUMENTS_BAD or CKR_GENERAL_ERROR for invalid inputs

#### S2: C_InitToken Edge Cases Beyond Length — High Priority (Destructive)

- **Existing coverage:** `test_ffi_null_pointer.py` (NULL PIN/label), `test_ckr_destructive.py` (wrong SO PIN, open session), `test_so_pin.py`
- **Missing probes:**
  - 0-length PIN
  - Maximum-length label (32 bytes)
  - Effects on existing sessions and objects after re-init
  - Called from RO session (should fail with CKR_SESSION_READ_ONLY_EXISTS)
- **Best location:** `testcases/test_destructive_token_policy.py` (new file)
- **Classification:** lifecycle (claimed success then state inconsistent)

#### S3: C_InitPIN Edge Cases — High Priority (Destructive)

- **Existing coverage:** `test_ckr_destructive.py`, `test_access_levels.py`
- **Missing probes:**
  - Maximum-length PIN
  - Re-InitPIN on SO session after previous InitPIN
  - Effect on existing USER session login state
  - Called from non-SO session
- **Best location:** `testcases/test_destructive_token_policy.py` (new file)

#### S4: C_SetPIN Edge Cases — Medium Priority (Destructive)

- **Existing coverage:** `test_ffi_null_pointer.py`, `test_ckr_destructive.py`, `test_so_pin.py`
- **Missing probes:**
  - Same old and new PIN
  - New PIN exceeding module maximum
  - Without prior login (should fail with CKR_USER_NOT_LOGGED_IN)
  - On RO session (should fail with CKR_SESSION_READ_ONLY_EXISTS)
- **Best location:** `testcases/test_destructive_token_policy.py` (new file)

#### S5: Session Handle Reuse Crash Probe — High Priority

- **Existing coverage:** `test_session_state_machine.py` (stale handle → C_GenerateRandom only)
- **Missing crash-safe probes:**
  - Systematic probing of ALL operations on a stale session handle (C_Encrypt, C_Sign, C_Digest, C_FindObjects, C_CreateObject, etc.)
  - Each probe in subprocess via `run_raw_subprocess`
  - Expect CKR_SESSION_HANDLE_INVALID or CKR_SESSION_CLOSED; crash = fail
- **Best location:** `testcases/security/test_api_boundary.py` (extend) or new `testcases/security/test_stale_handle_probe.py`
- **Classification:** lifecycle (claimed handle closed then accepted operations)

#### S6: Object Handle Validity Across Sessions — High Priority

- **Existing coverage:** `test_session_state_machine.py`, `test_object_visibility.py`
- **Missing crash-safe probes:**
  - Using a session-object handle after the creating session is closed (subprocess probe)
  - Using a session-object handle from a different concurrent session
  - Object handle reuse after C_DestroyObject across sessions
- **Best location:** `testcases/security/test_handle_reuse.py` (extend) or new file
- **Classification:** lifecycle

#### S7: C_GetFunctionStatus / C_CancelFunction Edge Cases — Low Priority

- **Existing coverage:** `test_remaining_gaps.py` (CKR_FUNCTION_NOT_PARALLEL)
- **Missing probes:** Invalid session handle, NULL session handle, session with active operation
- **Best location:** `testcases/test_remaining_gaps.py`

### Section Boundary Clarifications

Two pairs of sections have overlapping scope:

1. **"Secret-Key CKA_VALUE_LEN Over-Capacity" vs. "Scalar Attribute Length Validation"** — Split by attribute: CKA_VALUE_LEN (variable-length, crypto-semantic) vs. other scalar attributes (boolean, enum). Boundary: CKA_VALUE_LEN is tested for semantic correctness (key material truncation); other scalars are tested for length-format compliance.

2. **"Data Length Truncation" vs. "Other Caller-Controlled Length Surfaces"** — Split by direction: input data lengths on crypto operations vs. output buffer sizing and management API lengths. Boundary: "input claimed length" vs. "output buffer sizing".

---

## REFERENCES

- Original analysis: `docs/findings/pkcs11-hardening-test-gap-notes-2026-06-08.md`
- Classification model: `docs/classification-model-design.md`
- Architecture: `docs/architecture.md`
- Module issues: `docs/module-issues.md`
- Commands: `docs/commands.md`
