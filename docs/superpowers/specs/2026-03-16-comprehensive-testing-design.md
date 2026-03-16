# p11test Comprehensive Testing Design Specification

**Date:** 2026-03-16
**Status:** Draft
**Depends on:** `2026-03-16-p11test-design.md` (Phase 1 spec)

## 1. Overview

Expand p11test from ~85 basic tests to a comprehensive PKCS#11 test suite covering
cryptographic correctness, security attack vectors, robustness, performance, compliance,
and full v3.0/v3.2 coverage including PQC, plus vendor mechanism extensibility
(8 vendors, 71 vendor-specific mechanisms), and surface audit probing for hidden
capabilities. Target: ~2,400+ tests that match or exceed
coverage of Google pkcs11test, Galois model-based testing, and Wycheproof edge-case
vectors.

## 2. Test Categories

### 2.1 Cross-Verification Tests (`test_crossverify.py`)

Perform crypto operations via PKCS#11, then verify results independently using
Python's `cryptography` library. This proves the HSM computed correctly.

**Pattern:**
```
1. Import known key material into PKCS#11 (or generate + export public key)
2. Perform operation via PKCS#11
3. Repeat same operation with `cryptography` using same key material
4. Assert results match
```

**Coverage:**

| Operation | PKCS#11 side | Verification side |
|-----------|-------------|-------------------|
| AES-CBC encrypt | Import known key → encrypt | `cryptography` AES-CBC encrypt → compare ciphertext |
| AES-GCM encrypt | Import key → encrypt with IV+AAD | `cryptography` AES-GCM encrypt → compare ct+tag |
| RSA-PKCS sign | Generate keypair → sign → export pubkey | `cryptography` verify with public key |
| RSA-PSS sign | Generate keypair → sign → export pubkey | `cryptography` verify with PSS params |
| RSA-OAEP encrypt | Import public key → encrypt | `cryptography` decrypt with private key |
| ECDSA sign | Generate keypair → sign → export pubkey | `cryptography` verify with public key |
| ECDH derive | Generate keypairs → derive shared secret | `cryptography` ECDH derive → compare |
| EdDSA sign | Generate Ed25519 keypair → sign → export pubkey | `cryptography` verify |
| SHA-256 digest | Digest via PKCS#11 | `hashlib.sha256` → compare |
| HMAC-SHA256 | Import key → HMAC | `hmac` module → compare |
| Key wrap (AES-KW) | Wrap key with known wrapping key | `cryptography` unwrap → compare material |
| EncryptMessage (v3.0) | MessageEncryptInit → EncryptMessage (AEAD) | `cryptography` AEAD → compare ct+tag |
| SignMessage (v3.0) | MessageSignInit → SignMessage | `cryptography` verify |
| ML-KEM encapsulate (v3.2) | C_EncapsulateKey → shared secret | liboqs or reference impl → compare |
| ML-DSA sign (v3.2) | C_SignMessage with ML-DSA | reference impl verify |

Estimated: ~55 tests.

### 2.2 NIST Known-Answer Test Vectors (`test_kat.py`)

Static test vectors from NIST CAVP — import key, compute, compare with known answer.

**Sources:**
- AES: NIST SP 800-38A (ECB, CBC, OFB, CFB, CTR), SP 800-38D (GCM)
- SHA: SHAVS (SHA-1, SHA-224/256/384/512)
- RSA: FIPS 186-4 signature vectors
- ECDSA: FIPS 186-4 P-256, P-384, P-521 vectors
- HMAC: FIPS 198-1 vectors
- AES-KW: RFC 3394 test vectors
- ML-KEM: NIST FIPS 203 (final, August 2024) KAT vectors (key generation, encapsulation, decapsulation)
- ML-DSA: NIST FIPS 204 (final, August 2024) KAT vectors (key generation, sign, verify)
- SLH-DSA: NIST FIPS 205 (final, August 2024) KAT vectors

**Implementation:** JSON files in `src/p11test/testcases/vectors/` loaded via
`@pytest.mark.parametrize`.

Estimated: ~60 tests (original ~30 + ~30 PQC KAT vectors).

### 2.3 Wycheproof Edge-Case Vectors (`test_wycheproof.py`)

Import test vectors from the [Wycheproof project](https://github.com/C2SP/wycheproof)
to catch cryptographic implementation bugs at boundary conditions.

**Coverage:**

| Algorithm | Vector count | What they catch |
|-----------|-------------|-----------------|
| AES-GCM | ~300 | Invalid tags, short IVs, IV reuse, AAD edge cases |
| AES-CBC-PKCS5 | ~100 | Invalid padding, empty plaintext, block boundary |
| RSA PKCS#1 v1.5 sign | ~200 | Bleichenbacher-style padding |
| RSA-OAEP | ~150 | Manger's attack vectors |
| RSA-PSS | ~100 | Salt length edge cases, empty message |
| ECDSA P-256/384/521 | ~300/curve | Point at infinity, DER encoding, special curve points |
| ECDH | ~200 | Invalid public keys, small subgroup, point not on curve |
| EdDSA Ed25519 | ~100 | Small-order points, cofactor issues |
| HMAC-SHA* | ~50 | Truncated MACs, key length edge cases |
| AES-KW (RFC 3394) | ~50 | Invalid unwrap, integrity check |

**Implementation:** Download Wycheproof JSON files into `src/p11test/testcases/vectors/wycheproof/`,
parse with a shared loader, parametrize tests. Each JSON file becomes one parametrized test function.

**Expected result handling:** Wycheproof vectors have `result: "valid"|"acceptable"|"invalid"`.
- `valid` → operation must succeed and produce the expected output
- `invalid` → operation must fail with an appropriate error code (see Section 10.3 for
  the required CKR_ result sets per category)
- `acceptable` → either success or graceful failure is acceptable; output must be
  checked for correctness when it succeeds

**Invalid vector requirements (tightened):**

For each `"invalid"` Wycheproof vector, the test asserts ALL of the following:
- For decrypt operations: error code is `CKR_ENCRYPTED_DATA_INVALID` or
  `CKR_ENCRYPTED_DATA_LEN_RANGE` (no other CKR_ values accepted)
- For verify operations: error code is `CKR_SIGNATURE_INVALID` or
  `CKR_SIGNATURE_LEN_RANGE`
- For unwrap operations: error code is `CKR_WRAPPED_KEY_INVALID`,
  `CKR_WRAPPED_KEY_LEN_RANGE`, or `CKR_ENCRYPTED_DATA_INVALID`
- No new objects were created as a side effect
- No session state was leaked (session is still usable for subsequent operations)
- The active operation was cleanly terminated (no C_EncryptFinal/C_DecryptFinal
  required to reset; or if required, that call returns a non-crash error)

Estimated: ~1,200 parametrized test cases.

### 2.4 Comprehensive Mechanism Coverage (`test_encrypt.py`, `test_sign.py` expanded)

Extend existing tests to cover every mechanism + parameter combination:

**Symmetric ciphers:**

| Mechanism | Parameters | Key sizes | Tests |
|-----------|-----------|-----------|-------|
| AES-ECB | none | 128, 192, 256 | encrypt/decrypt, KAT |
| AES-CBC | IV (16B) | 128, 192, 256 | encrypt/decrypt, KAT, padding |
| AES-CBC-PAD | IV (16B) | 128, 192, 256 | PKCS7 padding correctness |
| AES-OFB | IV (16B) | 128, 192, 256 | encrypt/decrypt, stream property, KAT |
| AES-CFB | IV (16B) | 128, 192, 256 | encrypt/decrypt, KAT |
| AES-CTR | counter block | 128, 256 | encrypt/decrypt, stream property |
| AES-GCM | IV + AAD + tagLen | 128, 256 | AEAD, tag verification, IV sizes |
| AES-CCM | nonce + AAD + tagLen | 128, 256 | AEAD |
| AES-CMAC | none | 128, 256 | MAC generation + verification |
| AES-KEY-WRAP | none | 128, 256 | RFC 3394 vectors |
| AES-KEY-WRAP-PAD | none | 128, 256 | RFC 5649 vectors |
| 3DES-CBC | IV (8B) | 168 | legacy support |
| 3DES-ECB | none | 168 | legacy support |

**RSA operations:**

| Mechanism | Parameters | Key sizes |
|-----------|-----------|-----------|
| RSA-PKCS | none | 2048, 3072, 4096 |
| RSA-PKCS-OAEP | hash × mgf combos | 2048, 4096 |
| RSA-PKCS-PSS | hash × mgf × saltLen | 2048, 4096 |
| RSA-X-509 | none (raw) | 2048 |
| SHA*-RSA-PKCS | hash variant | 2048, 4096 |
| SHA*-RSA-PKCS-PSS | hash × mgf × salt | 2048, 4096 |

**EC operations:**

| Mechanism | Curves |
|-----------|--------|
| EC-KEY-PAIR-GEN | P-256, P-384, P-521 |
| ECDSA | P-256, P-384, P-521 (raw, with pre-hash) |
| ECDSA-SHA* | combined hash+sign |
| ECDH1-DERIVE | P-256, P-384, P-521 |
| EC-EDWARDS-KEY-PAIR-GEN | Ed25519, Ed448 |
| EDDSA | Ed25519, Ed448 |

**Digests:**

| Mechanism | Output size |
|-----------|-------------|
| SHA-1 | 20 |
| SHA-224 | 28 |
| SHA-256 | 32 |
| SHA-384 | 48 |
| SHA-512 | 64 |
| MD5 | 16 (legacy) |

**HMAC:** SHA-1/256/384/512-HMAC with varying key sizes.

**Parameter space exhaustion for complex mechanisms:**
- AES-GCM: IV (12B, 1B, 16B, 32B) × tag (128, 120, 112, 104, 96) × AAD (0B, 16B, 1KB)
- RSA-OAEP: hash (SHA-1, 256, 384, 512) × MGF (MGF1-SHA-1, MGF1-SHA-256) × source (empty, custom)
- RSA-PSS: hash (SHA-256, 384, 512) × MGF (MGF1-same) × salt (0, 32, max)

### 2.5 Key Management Tests (`test_keymgmt.py`)

| Operation | Tests |
|-----------|-------|
| Key import (C_CreateObject) | Import AES, RSA, EC raw key material → use → cross-verify |
| Key export | Export public keys → parse with `cryptography` → verify encoding |
| Key wrap/unwrap | AES-KW, AES-CBC, RSA-PKCS, RSA-OAEP round-trips → cross-verify |
| Key derive (ECDH) | Derive shared secret → cross-verify with `cryptography` |
| Key derive (DH) | DH parameter gen → key exchange → derive |
| Key copy (C_CopyObject) | Copy → verify attributes preserved |
| PKCS#8 import | Import PKCS#8 encoded private key |
| X.509 cert round-trip | Import cert DER → C_GetAttributeValue → parse → verify fields |
| EC public key encoding | Export EC key → verify ASN.1 DER OID + point |
| RSA modulus/exponent | Export → verify BER/DER correctness |

Estimated: ~25 tests.

### 2.6 Multi-Part & Dual-Function Operations (`test_multipart.py`)

| Operation | Functions | Tests |
|-----------|----------|-------|
| Encrypt multi-part | C_EncryptUpdate + Final | 1B, 15B, 16B, 1MB chunks; compare to single-shot |
| Decrypt multi-part | C_DecryptUpdate + Final | same |
| Sign multi-part | C_SignUpdate + Final | chunked data, compare signature to single-shot |
| Verify multi-part | C_VerifyUpdate + Final | chunked verification |
| Digest multi-part | C_DigestUpdate + Final | incremental hash, compare to single-shot |
| DigestKey | C_DigestKey | hash key value directly |
| Digest+Encrypt | C_DigestEncryptUpdate | simultaneous |
| Decrypt+Digest | C_DecryptDigestUpdate | simultaneous |
| Sign+Encrypt | C_SignEncryptUpdate | simultaneous |
| Decrypt+Verify | C_DecryptVerifyUpdate | simultaneous |

Estimated: ~20 tests.

### 2.7 Access Control & Attribute Enforcement (`test_access.py`)

**Key usage restrictions:**

| Attribute | Test |
|-----------|------|
| CKA_ENCRYPT=False | C_EncryptInit must return CKR_KEY_FUNCTION_NOT_PERMITTED |
| CKA_DECRYPT=False | C_DecryptInit must fail |
| CKA_SIGN=False | C_SignInit must fail |
| CKA_VERIFY=False | C_VerifyInit must fail |
| CKA_WRAP=False | C_WrapKey must fail |
| CKA_UNWRAP=False | C_UnwrapKey must fail |
| CKA_EXTRACTABLE=False | C_GetAttributeValue(CKA_VALUE) must fail |
| CKA_SENSITIVE=True | Private key material not readable |
| CKA_MODIFIABLE=False | C_SetAttributeValue must fail |
| CKA_COPYABLE=False | C_CopyObject must fail |
| CKA_DESTROYABLE=False | C_DestroyObject must fail |
| CKA_PRIVATE=True | Object not visible without login |
| CKA_ALWAYS_SENSITIVE | Attribute tracks correctly post-generation |
| CKA_NEVER_EXTRACTABLE | Attribute tracks correctly |

**Session & login matrix:**

| Scenario | Test |
|----------|------|
| R/O session | Generate key must fail |
| R/W session | Generate key succeeds |
| Public (no login) | Only public objects visible |
| User login | Private objects visible |
| SO login | Can C_InitPIN, cannot do crypto |
| Session object lifetime | Close session → object gone |
| Token object lifetime | Close/reopen → object persists |
| Multiple sessions | Independent operations |
| Concurrent R/O + R/W | R/O can't write, R/W can |

Estimated: ~25 tests.

### 2.8 Token Management — Destructive (`test_token.py`)

All require `@pytest.mark.destructive`:

| Operation | Test |
|-----------|------|
| C_InitToken | Wipe and reinitialize → verify empty |
| C_InitPIN | Set user PIN → login with new PIN |
| C_SetPIN | Change PIN → old fails, new works |
| SO PIN change | Change SO PIN |
| PIN retry | Wrong PIN → CKR_PIN_INCORRECT |
| Token label | Set label → verify via C_GetTokenInfo |
| Create persistent object | CKA_TOKEN=True → survives session close |
| Destroy persistent object | CKA_TOKEN=True → destroy → gone after reopen |

**PIN and lockout persistence (all `@pytest.mark.destructive`):**

| Operation | Test |
|-----------|------|
| PIN retry counter | Wrong PIN N times → verify CKR_PIN_INCORRECT and counter decrements (C_GetTokenInfo.ulMaxPinLen for reference) |
| Lockout | Exhaust PIN retries → verify CKR_PIN_LOCKED |
| Lockout persistence | Lock → close session → reopen session → still CKR_PIN_LOCKED |
| SO reset | SO login → C_InitPIN → user PIN reset → user can log in again |
| Lockout across Finalize/Initialize | Lock token → C_Finalize → C_Initialize → still CKR_PIN_LOCKED |

Estimated: ~15 tests.

### 2.9 Object Search & Enumeration (`test_search.py`)

| Scenario | Test |
|----------|------|
| Empty template | Returns all objects |
| By class (SECRET_KEY, PUBLIC_KEY) | Correct filtering |
| By label | Exact match |
| By multiple attributes | Class + Label + KeyType |
| No results | Nonexistent label → 0 results |
| Large result set | Create 100 objects → FindObjects returns all |
| Interleaved find | Two overlapping C_FindObjects sequences → must error |

Estimated: ~10 tests.

### 2.10 Error Conditions — Galois Style (`test_errors.py` expanded)

Inspired by Galois model-based testing: test every error code path in the spec.

| Category | Tests |
|----------|-------|
| Wrong state | Encrypt without EncryptInit, Sign after Finalize |
| Invalid params | Wrong IV size, NULL buffer, zero-length output |
| Wrong key type | Sign with AES key, encrypt with ECDSA key |
| Permission denied | CKA_ENCRYPT=False, use non-extractable for wrap |
| Buffer too small | Output buffer insufficient → CKR_BUFFER_TOO_SMALL |
| Invalid mechanism | Unsupported mechanism for operation |
| Session errors | Operation on closed session |
| Object errors | Use destroyed object handle |
| State machine violations | Update without Init, Final without Update |
| Double init | C_EncryptInit twice without encrypt between them |
| Mechanism param errors | GCM with null IV, CBC with 15-byte IV |

Estimated: ~30 tests.

### 2.11 Mechanism Flags Validation (`test_mechflags.py`)

| Test | Description |
|------|-------------|
| CKF_ENCRYPT consistency | If mechanism has flag, EncryptInit succeeds; if not, fails |
| CKF_SIGN consistency | Same for sign/verify |
| CKF_WRAP consistency | Same for wrap/unwrap |
| CKF_DERIVE consistency | Same for derive |
| CKF_GENERATE consistency | Same for generate |
| Key size in range | Generate with reported min/max → must succeed |
| Key size out of range | Below min or above max → must fail |

Estimated: ~10 tests.

### 2.12 Additional PKCS#11 Functions

The following PKCS#11 functions are covered in their respective existing test files:

**C_WaitForSlotEvent (`test_slot.py`):**

| Test | Description |
|------|-------------|
| Non-blocking mode | C_WaitForSlotEvent(CKF_DONT_BLOCK) → returns CKR_NO_EVENT when no event pending |
| Blocking mode (stub) | C_WaitForSlotEvent(0) with stub that fires event → returns event info |

**C_SeedRandom (`test_rng.py`):**

| Test | Description |
|------|-------------|
| Seed + generate | C_SeedRandom(seed_bytes) → C_GenerateRandom → verify output differs from pre-seed output |
| Empty seed | C_SeedRandom(b"") → CKR_OK or CKR_ARGUMENTS_BAD (record behavior) |

**C_SignRecover / C_VerifyRecover (`test_sign.py`):**

| Test | Description |
|------|-------------|
| Sign + recover round-trip | C_SignRecoverInit → C_SignRecover → C_VerifyRecoverInit → C_VerifyRecover → recovered data matches original |
| Unsupported mechanism | If mechanism doesn't support recovery, must return CKR_FUNCTION_NOT_SUPPORTED |

These tests carry `@pytest.mark.needs_mechanism("RSA_PKCS")` as appropriate and are
skipped when the mechanism is unavailable.

**C_DigestEncryptUpdate / C_DecryptDigestUpdate (`test_multipart.py`):**

These dual-function operations are explicitly tested (see Section 2.6) by verifying
that the digest output and the encrypt output each independently match their single-function
equivalents.

Estimated: ~10 additional tests across the named files.

## 3. v3.x Testing

This chapter covers all v3.0 and v3.2 functions from the base design spec Section 5.
Tests in this chapter carry `@pytest.mark.requires_v30` or `@pytest.mark.requires_v32`
and are automatically skipped when the negotiated interface version is insufficient.

### 3.1 Message-Based Operations (`test_message.py`)

v3.0 introduced a message-based paradigm where a single Init call covers a sequence
of independent messages, avoiding repeated InitEncrypt/InitDecrypt overhead for
protocols like TLS record layer and AEAD streaming.

**Message encryption (C_MessageEncryptInit / C_EncryptMessage / C_EncryptMessageBegin
/ C_EncryptMessageNext / C_MessageEncryptFinal):**

| Test | Description |
|------|-------------|
| Single-message round-trip | MessageEncryptInit → EncryptMessage → MessageDecryptInit → DecryptMessage → compare plaintext |
| Multi-message sequence | MessageEncryptInit → EncryptMessage × 10 → MessageEncryptFinal → verify each message independent |
| Begin/Next single chunk | EncryptMessageBegin → EncryptMessageNext (all in one) → compare to EncryptMessage |
| Begin/Next multi-chunk | EncryptMessageBegin → EncryptMessageNext × N → compare to single-shot |
| IV/nonce uniqueness | Encrypt 100 messages under same Init → all IVs unique (for AEAD modes) |
| AES-GCM message mode | Full round-trip with AAD per message |
| ChaCha20-Poly1305 | Full round-trip (if supported) |
| MessageEncryptFinal without begin | Must return CKR_OPERATION_NOT_INITIALIZED |
| EncryptMessage after Final | Must return CKR_OPERATION_NOT_INITIALIZED |
| Cross-verify with cryptography | EncryptMessage output → `cryptography` decrypt → compare |

**Message decryption (symmetric to above):** ~10 tests mirroring message encryption.

**Message signing (C_MessageSignInit / C_SignMessage / C_SignMessageBegin /
C_SignMessageNext / C_MessageSignFinal):**

| Test | Description |
|------|-------------|
| ECDSA message sign round-trip | MessageSignInit → SignMessage → MessageVerifyInit → VerifyMessage |
| RSA-PSS message sign | Same pattern |
| Multi-message signing | 10 messages, each independently verified |
| Begin/Next chunked sign | SignMessageBegin → SignMessageNext × N → verify output |
| Cross-verify | SignMessage output → `cryptography` verify |

**Message verification (symmetric):** ~5 tests mirroring message signing.

Estimated: ~40 tests.

### 3.2 Async Operations (`test_async.py`)

v3.2 async functions allow non-blocking submission of long-running operations.

| Test | Description |
|------|-------------|
| C_AsyncGetID basic | Submit async RSA keygen → GetID returns valid handle |
| C_AsyncComplete poll | GetID → poll AsyncComplete → result available |
| C_AsyncJoin wait | Submit → AsyncJoin blocks until done → verify result |
| Concurrent async ops | Submit 4 RSA keygens in parallel → join all → all succeed |
| AsyncComplete before done | Poll immediately → CKR_ASYNC_OPERATION_PENDING (if still running) |
| Invalid async handle | AsyncComplete with bogus handle → CKR_OBJECT_HANDLE_INVALID or similar |
| Async keygen cross-verify | Async-generated EC key → sign → `cryptography` verify |
| Async operation cancellation | If C_SessionCancel is called mid-async → clean termination |

Estimated: ~10 tests.

### 3.3 KEM and Post-Quantum Cryptography (`test_pqc.py`)

v3.2 added KEM operations and PQC algorithm support. KAT vectors are sourced from
NIST FIPS 203 (ML-KEM, final August 2024), FIPS 204 (ML-DSA, final August 2024),
and FIPS 205 (SLH-DSA, final August 2024) test vector sets.

**ML-KEM (C_EncapsulateKey / C_DecapsulateKey):**

| Test | Description |
|------|-------------|
| ML-KEM-512 keygen + encapsulate + decapsulate | Full round-trip, shared secrets match |
| ML-KEM-768 round-trip | Same |
| ML-KEM-1024 round-trip | Same |
| KAT vector: ML-KEM-768 encapsulate | Known key → encapsulate → compare ciphertext |
| KAT vector: ML-KEM-768 decapsulate | Known ciphertext → decapsulate → compare shared secret |
| C_EncapsulateKey with wrong key type | Non-KEM key → CKR_KEY_TYPE_INCONSISTENT |
| Decapsulate with modified ciphertext | Flip one bit → shared secret must differ (FO transform) |
| Decapsulate with empty ciphertext | → must fail cleanly |
| Cross-verify with liboqs reference | Encapsulate in PKCS#11 → decapsulate with liboqs |
| CKA_SENSITIVE on decap key | Shared secret derivation only, key material not exportable |

**ML-DSA (sign via C_SignMessage / C_VerifyMessage or C_SignInit / C_VerifyInit):**

| Test | Description |
|------|-------------|
| ML-DSA-44 sign + verify round-trip | Generate keypair → sign → verify |
| ML-DSA-65 round-trip | Same |
| ML-DSA-87 round-trip | Same |
| KAT vector: ML-DSA-65 sign | Known key + message → compare signature |
| KAT vector: ML-DSA-65 verify | Known signature → verify |
| Cross-verify with liboqs | Sign in PKCS#11 → verify with liboqs reference |
| Modified message | Valid signature + different message → CKR_SIGNATURE_INVALID |

**SLH-DSA:**

| Test | Description |
|------|-------------|
| SLH-DSA-SHAKE-128s round-trip | Generate keypair → sign → verify |
| KAT vector: SLH-DSA-SHAKE-128s | Known key + message → compare signature |
| Cross-verify with liboqs | Sign in PKCS#11 → verify with liboqs reference |

Estimated: ~30 tests.

### 3.3a C_VerifySignature* Family (v3.2, `test_pqc.py` / `test_sign.py`)

v3.2 introduced a new single-shot and multi-part verification family
(`C_VerifySignatureInit`, `C_VerifySignature`, `C_VerifySignatureUpdate`,
`C_VerifySignatureFinal`) that is separate and distinct from the classic
`C_VerifyInit` / `C_Verify` / `C_VerifyUpdate` / `C_VerifyFinal` family.
The new family is designed to support PQC signature algorithms (ML-DSA, SLH-DSA)
where the signature is provided as an input parameter rather than appended after
the data.

**Functions:**

| Function | Role |
|----------|------|
| `C_VerifySignatureInit` | Initialize single-shot or multi-part PQC verification |
| `C_VerifySignature` | Single-shot verify (analogous to `C_Verify` in the classic family) |
| `C_VerifySignatureUpdate` | Supply data incrementally for multi-part verification |
| `C_VerifySignatureFinal` | Finalize multi-part verification |

**Tests:**

| Test | Description |
|------|-------------|
| ML-DSA sign + VerifySignature (single-shot) | C_SignInit (ML-DSA) → C_Sign → C_VerifySignatureInit → C_VerifySignature |
| ML-DSA sign + VerifySignatureUpdate/Final | C_Sign → C_VerifySignatureInit → C_VerifySignatureUpdate × N → C_VerifySignatureFinal |
| SLH-DSA sign + VerifySignature | Same pattern for SLH-DSA |
| SLH-DSA multi-part verify | C_VerifySignatureInit → C_VerifySignatureUpdate × N → C_VerifySignatureFinal |
| Cross-verify with reference impl | Sign in PKCS#11 → verify with liboqs using same key material |
| VerifySignature with tampered message | Valid signature, different message → CKR_SIGNATURE_INVALID |
| VerifySignature with tampered signature | Valid message, flipped bit in signature → CKR_SIGNATURE_INVALID |
| VerifySignature without VerifySignatureInit | → CKR_OPERATION_NOT_INITIALIZED |
| Classic C_Verify still works for EC/RSA | Verify that C_VerifyInit / C_Verify still operates correctly (not displaced by new family) |

These tests carry `@pytest.mark.requires_v32` and are skipped when the negotiated
interface is below v3.2.

Estimated: ~10 tests.

### 3.4 Authenticated Wrap/Unwrap (`test_authwrap.py`)

v3.2 `C_WrapKeyAuthenticated` and `C_UnwrapKeyAuthenticated` add AEAD integrity
protection to the key wrapping envelope.

| Test | Description |
|------|-------------|
| AES-GCM authenticated wrap round-trip | WrapKeyAuthenticated → UnwrapKeyAuthenticated → verify key usable |
| AAD included | Wrap with AAD → unwrap with same AAD → success |
| AAD mismatch | Wrap with AAD "ctx-A" → unwrap with AAD "ctx-B" → must fail |
| Tag truncation | Truncate wrapped blob by 1 byte → unwrap → CKR_WRAPPED_KEY_INVALID |
| Bit flip in wrapped key | Flip one byte in wrapped data → unwrap → must fail |
| Bit flip in tag | Flip one byte in authentication tag → unwrap → must fail |
| Attribute override after authenticated unwrap | Unwrap with template CKA_EXTRACTABLE=True when wrapped key was CKA_EXTRACTABLE=False → module must reject or sanitize |
| No new object on tamper failure | After failed unwrap, verify no object handle was created |
| Session still usable after tamper | Failed unwrap → session still accepts new operations |
| Cross-verify | WrapKeyAuthenticated → Python `cryptography` AES-GCM unwrap → compare raw key bytes |

Estimated: ~12 tests.

### 3.5 Profile Validation (`test_profiles.py`)

v3.0 introduced profile objects (CKO_PROFILE) representing supported conformance profiles.

| Test | Description |
|------|-------------|
| Enumerate CKO_PROFILE objects | C_FindObjects with CKO_PROFILE → list all profiles |
| CKP_BASELINE_PROVIDER presence | If v3.0 module, baseline provider profile expected |
| CKP_EXTENDED_PROVIDER | If claimed, verify extended algorithms available |
| CKP_AUTHENTICATION_TOKEN | If claimed, verify auth-only behaviors |
| CKP_PUBLIC_CERTIFICATES_TOKEN | If claimed, cert storage behaviors |
| Profile attribute read | CKA_PROFILE_ID readable for each profile object |
| Profile vs mechanism consistency | Claimed profile algorithms all appear in C_GetMechanismList |
| No profile objects on v2.40 | v2.40 module → C_FindObjects(CKO_PROFILE) returns 0 results |

Estimated: ~10 tests.

### 3.6 Session Validation Flags (`test_session_validation.py`)

v3.2 `C_GetSessionValidationFlags` allows querying per-session security state.

| Test | Description |
|------|-------------|
| Flags after fresh login | Retrieve flags immediately after C_Login |
| Flags without login | Public session → query flags → expected subset |
| CKF_TOKEN_OK | Verify flag present when token healthy |
| CKF_SIDE_CHANNEL_OUT_OF_RANGE | If supported, trigger and detect side-channel flag |
| Flags after re-login | Logout → login → flags reset correctly |
| Invalid session handle | C_GetSessionValidationFlags with bogus handle → CKR_SESSION_HANDLE_INVALID |

Estimated: ~8 tests.

### 3.7 C_LoginUser (v3.0 Username-Based Login)

v3.0 `C_LoginUser` extends `C_Login` with a username string argument for
multi-user tokens.

| Test | Description |
|------|-------------|
| C_LoginUser with valid credentials | Login with username + PIN → session active |
| C_LoginUser vs C_Login equivalence | Both produce equivalent logged-in state |
| C_LoginUser with wrong PIN | → CKR_PIN_INCORRECT |
| C_LoginUser with unknown username | → CKR_USER_NOT_LOGGED_IN or CKR_PIN_INCORRECT |
| C_LoginUser on v2.40 module | → CKR_FUNCTION_NOT_SUPPORTED (graceful) |
| Objects visible after C_LoginUser | Private objects accessible after user login |

Estimated: ~8 tests.

### 3.8 C_SessionCancel (v3.0)

| Test | Description |
|------|-------------|
| Cancel active encrypt operation | EncryptInit → SessionCancel → EncryptUpdate → CKR_OPERATION_CANCELLED or NOT_INITIALIZED |
| Cancel active sign operation | SignInit → SessionCancel → SignUpdate → expected error |
| Cancel with no active operation | SessionCancel on idle session → CKR_OPERATION_NOT_INITIALIZED |
| Cancel on invalid session | Bogus handle → CKR_SESSION_HANDLE_INVALID |
| Session usable after cancel | Cancel → start new operation on same session → succeeds |
| Cancel during async op | Submit async → SessionCancel → async result is error |

Estimated: ~8 tests.

### 3.9 Interface Negotiation Edge Cases

These tests exercise the loader logic from base design spec Section 4, using a
configurable stub module for fault injection.

| Test | Description |
|------|-------------|
| C_GetInterface returns NULL pointer | Loader falls back to C_GetFunctionList |
| C_GetInterface crashes (via stub) | Loader catches crash, falls back, reports finding |
| v3.2 interface with NULL function pointers | Report as finding, skip tests for those functions |
| v3.0 interface partially populated | Only v2.40 subset works → v3.0 tests skip |
| --interface 3.2 on v2.40 module | Exit code 3, clear error message |
| C_GetInterfaceList enumeration | All interfaces returned → choose highest supported |
| Duplicate interface entries | Loader deduplicates, picks highest |
| Interface version mismatch | Module reports 3.2 but function list is 3.0 size → detect mismatch |

Estimated: ~10 tests.

### 3.10 v3.x Cross-Verification

Cross-verification tests for v3.x operations confirm that PKCS#11 v3.x output is
cryptographically equivalent to independent implementations.

| Operation | PKCS#11 side | Verification side |
|-----------|-------------|-------------------|
| EncryptMessage AES-GCM | MessageEncryptInit → EncryptMessage | `cryptography` AES-GCM decrypt |
| SignMessage ECDSA | MessageSignInit → SignMessage | `cryptography` ECDSA verify |
| EncapsulateKey ML-KEM | C_EncapsulateKey | liboqs decapsulate |
| SignMessage ML-DSA | C_SignMessage | liboqs verify |
| WrapKeyAuthenticated | C_WrapKeyAuthenticated (AES-GCM) | `cryptography` AES-GCM unwrap |

These are subsumed within `test_crossverify.py` and the specific test files above.

### v3.x Test Count Summary

| Subcategory | Count |
|-------------|-------|
| Message-based operations | ~40 |
| Async operations | ~10 |
| KEM/PQC | ~30 |
| Authenticated wrap/unwrap | ~12 |
| Profile validation | ~10 |
| Session validation flags | ~8 |
| C_LoginUser | ~8 |
| C_SessionCancel | ~8 |
| Interface negotiation edge cases | ~10 |
| **v3.x subtotal** | **~136** |

## 4. Security Testing

### 4.1 PKCS#11 API Security Attacks (`test_api_security.py`)

From Bortolozzo et al. "Attacking and Fixing PKCS#11 Security Tokens" (CCS 2010)
and related work on PKCS#11 policy abuse:

**Classic attribute attacks:**

| Attack vector | Test |
|---------------|------|
| Wrap-decrypt oracle | Key with CKA_WRAP + CKA_DECRYPT → wrap under self → decrypt = extract key. Module SHOULD prevent this. |
| Sensitive extraction | CKA_SENSITIVE key → C_GetAttributeValue(CKA_VALUE) → must fail |
| Attribute escalation via SetAttributeValue | Set CKA_EXTRACTABLE=True after creation with False → must fail |
| Key role confusion | Use signing key for encryption |
| Re-import as wrapping key | Export public key → re-import with CKA_WRAP → attempt wrapping |

**Attribute laundering — C_CopyObject:**

| Test | Description |
|------|-------------|
| CopyObject escalates CKA_EXTRACTABLE | Copy key with CKA_EXTRACTABLE=False, supply template CKA_EXTRACTABLE=True → must fail or produce non-extractable copy |
| CopyObject removes CKA_SENSITIVE | Copy key with CKA_SENSITIVE=True, supply template CKA_SENSITIVE=False → must fail or preserve sensitive |
| CopyObject adds CKA_WRAP | Copy key without CKA_WRAP=True, supply template CKA_WRAP=True → must fail if original never had wrap permission |
| CopyObject modifies CKA_TOKEN | Session object → copy with CKA_TOKEN=True without permission → verify module rejects or that object is properly governed |
| Post-copy attribute audit | After any successful copy, read back actual attributes → verify no unexpected escalation occurred |

**Attribute laundering — C_DeriveKey:**

| Test | Description |
|------|-------------|
| DeriveKey overrides CKA_SENSITIVE | Derive from sensitive key, supply template CKA_SENSITIVE=False → module must reject or ignore override |
| DeriveKey overrides CKA_EXTRACTABLE | Derive from non-extractable key, supply template CKA_EXTRACTABLE=True → module must reject |
| DeriveKey overrides CKA_DECRYPT | Derive key with template CKA_DECRYPT=True when parent context doesn't allow it |
| Post-derive attribute audit | After allowed derive, verify CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE are downgraded if parent was non-extractable |

**Attribute laundering — C_UnwrapKey:**

| Test | Description |
|------|-------------|
| UnwrapKey overrides CKA_SENSITIVE | Unwrap with template CKA_SENSITIVE=False → module must reject or force True |
| UnwrapKey overrides CKA_EXTRACTABLE | Unwrap with template CKA_EXTRACTABLE=True → module must reject or downgrade |
| UnwrapKey sets CKA_WRAP on unwrapped key | Unwrap symmetric key with template CKA_WRAP=True to enable further wrapping |
| Post-unwrap attribute audit | Verify attributes on unwrapped key, confirm no unexpected escalation |

**CKA_ALLOWED_MECHANISMS enforcement:**

| Test | Description |
|------|-------------|
| Create key with CKA_ALLOWED_MECHANISMS | Set allowed mechanisms list on AES key (e.g., only AES-GCM) |
| Use key with allowed mechanism | AES-GCM with restricted key → must succeed |
| Use key with disallowed mechanism | AES-CBC with AES-GCM-only key → must return CKR_MECHANISM_INVALID or CKR_KEY_FUNCTION_NOT_PERMITTED |
| Empty allowed mechanisms list | No mechanisms allowed → all operations fail |
| CopyObject preserves allowed mechanisms | Copy key → verify CKA_ALLOWED_MECHANISMS carried over |
| DeriveKey propagates restrictions | Derived key inherits restricted mechanisms |

**CKA_WRAP_WITH_TRUSTED and CKA_TRUSTED:**

| Test | Description |
|------|-------------|
| Create CKA_TRUSTED wrapping key | Only SO can set CKA_TRUSTED=True; user attempt → must fail |
| Wrap CKA_WRAP_WITH_TRUSTED key | Key has CKA_WRAP_WITH_TRUSTED=True → only trusted wrapping keys can wrap it |
| Wrap with non-trusted key | Attempt to wrap CKA_WRAP_WITH_TRUSTED key with non-trusted AES key → must fail |
| Verify trusted flag immutability | After SO sets CKA_TRUSTED=True, user cannot change it |

**CKA_ALWAYS_AUTHENTICATE:**

| Test | Description |
|------|-------------|
| Create key with CKA_ALWAYS_AUTHENTICATE=True | Key requires re-auth before each use |
| Operation without re-auth | SignInit → SignUpdate → SignFinal without intermediate re-auth → must fail with CKR_USER_NOT_AUTHORIZED or CKR_PIN_EXPIRED |
| Operation with re-auth | SignInit → C_Login(CKU_CONTEXT_SPECIFIC) → SignFinal → must succeed |
| Second operation without re-auth | First op succeeds → second SignInit → again requires re-auth |

**Login/logout invalidation:**

| Test | Description |
|------|-------------|
| Logout cancels active encrypt | EncryptInit → C_Logout → C_EncryptUpdate → must return CKR_USER_NOT_LOGGED_IN or operation cancelled |
| Logout cancels active sign | Same for sign |
| Logout during multi-message | MessageSignInit → C_Logout → SignMessage → must fail |
| Login cancels in-progress operation | Logout → Login (re-auth) → previous operation handle invalid |

**C_GetOperationState / C_SetOperationState abuse:**

| Test | Description |
|------|-------------|
| Export operation state | EncryptInit → GetOperationState → blob |
| Replay exported state | GetOperationState → SetOperationState (same session) → continue → verify result |
| Cross-session state replay | GetOperationState (session A) → SetOperationState (session B) → if allowed, verify result; if rejected, verify CKR_SAVED_STATE_INVALID |
| Tampered state | GetOperationState → flip 1 byte → SetOperationState → must fail or produce wrong result (classified as security finding if it succeeds) |
| State replay after finalize | GetOperationState before Final → Final → SetOperationState → attempt second Final → must fail |

**Private object search leakage:**

| Test | Description |
|------|-------------|
| Search before login | C_FindObjects with empty template → only public objects returned |
| Search for private label before login | C_FindObjects with known private object label → must return 0 results (existence not revealed) |
| Search for private object count | Verify count of returned handles matches expectation (no leakage via count) |
| Login then search | After login, same search → private objects returned normally |

**Cross-process RNG duplicate detection after fork/spawn:**

| Test | Description |
|------|-------------|
| Spawn two subprocesses, collect RNG | Each subprocess calls C_GenerateRandom(32) × 100 → all 200 results unique |
| RNG independence after fork | Fork two processes after C_Initialize → RNG outputs diverge immediately |
| Nonce uniqueness across sessions | Open 4 parallel sessions → each generates 100 nonces → all 400 unique |

Estimated: ~70 tests total across all attack subcategories.

### 4.2 Padding Oracle Detection (`test_padding_oracle.py`)

From Bardou et al. (2012):

| Test | Description |
|------|-------------|
| RSA PKCS#1 v1.5 error uniformity | Decrypt valid vs invalid ciphertext → error code must be identical |
| RSA PKCS#1 v1.5 timing | 1000 valid + 1000 invalid decrypts → timing difference < threshold |
| AES-CBC padding error uniformity | Corrupt last byte vs middle byte → same error code |
| OAEP error uniformity | Invalid OAEP → all errors should be CKR_ENCRYPTED_DATA_INVALID |

Estimated: ~8 tests.

### 4.3 ECDSA Nonce Quality (`test_nonce_quality.py`)

From Trail of Bits "ECDSA: Handle with Care" and PuTTY CVE-2024-31497:

| Test | Description |
|------|-------------|
| Nonce reuse | Sign same message 100× → all `r` values unique (if any repeat → CRITICAL) |
| Nonce bias (upper bits) | 10,000 signatures → statistical test on `r` distribution |
| Deterministic check (RFC 6979) | Sign same message twice → if r,s identical → deterministic (report) |
| P-521 upper-bit bias | Specifically check for PuTTY-style 9-bit bias on P-521 |

Estimated: ~5 tests.

### 4.4 Timing Side-Channel (`test_timing.py`)

| Test | Description |
|------|-------------|
| RSA decrypt timing | Valid vs invalid ciphertext → t-test, N=1000 |
| HMAC verify timing | Correct vs incorrect MAC → t-test |
| Signature verify timing | Valid vs invalid signature → t-test |

Note: Timing tests are **informational** — flagged as warnings with confidence intervals.
Statistical significance threshold: p < 0.001.

Estimated: ~8 tests.

### 4.5 Known CVE Regression (`test_regressions.py`)

| CVE/Bug | Test |
|---------|------|
| ROCA (CVE-2017-15361) | Check RSA public key for Infineon vulnerability fingerprint |
| PuTTY P-521 bias (CVE-2024-31497) | Check for nonce bias in first 9 bits |
| ROBOT attack | RSA PKCS#1 v1.5 error oracle check |

Estimated: ~10 tests.

## 5. Stateful Model Testing (`test_stateful.py`)

This section specifies model-based tests using `hypothesis.stateful.RuleBasedStateMachine`
to drive the PKCS#11 state machine in ways that manual test authoring cannot exhaustively
cover. Each state machine tests a specific state transition graph derived from the
PKCS#11 specification.

### 5.1 Session State Machine

The session state machine covers the lifecycle of a PKCS#11 session from open to close,
including the login/logout dimension.

**States:**
- `session_closed` — no session open
- `session_open_public` — session open, not logged in
- `session_open_user` — session open, user logged in
- `session_open_so` — session open, SO logged in

**Transitions (Rules):**
- `open_session` (from closed → public)
- `login_user` (from public → user)
- `login_so` (from public → SO)
- `logout` (from user/SO → public)
- `close_session` (from any open → closed)
- `login_wrong_pin` (from public → public, must return CKR_PIN_INCORRECT)
- `login_when_logged_in` (from user/SO → must return CKR_USER_ALREADY_LOGGED_IN)

**Invariants verified at every step:**
- Private objects not visible in `session_open_public` state
- Crypto operations fail in `session_open_so` state
- `C_GetSessionInfo` returns matching `state` field at every step

### 5.2 Login State Transitions

The login state machine specifically tests the full user/SO login matrix including
invalid transitions.

**States:** `logged_out`, `user_logged_in`, `so_logged_in`

**Rules:**
- `login_user` (from logged_out → user_logged_in)
- `login_so` (from logged_out → so_logged_in)
- `login_user_when_so` (from so_logged_in → must return CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
- `login_so_when_user` (from user_logged_in → must return CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
- `logout` (from user_logged_in or so_logged_in → logged_out)
- `logout_when_out` (from logged_out → must return CKR_USER_NOT_LOGGED_IN)
- `double_user_login` (from user_logged_in → must return CKR_USER_ALREADY_LOGGED_IN)

### 5.3 Operation Lifecycle

The operation lifecycle machine tests that the Init → Update* → Final pattern
is enforced and that illegal transitions are rejected.

**States:** `idle`, `encrypt_active`, `decrypt_active`, `sign_active`, `verify_active`,
`digest_active`

**Rules (examples for encrypt; mirrored for decrypt/sign/verify/digest):**
- `encrypt_init` (from idle → encrypt_active)
- `encrypt_update` (from encrypt_active → encrypt_active)
- `encrypt_final` (from encrypt_active → idle)
- `encrypt_init_twice` (from encrypt_active → must cancel previous or return error, then enter new encrypt_active)
- `encrypt_update_without_init` (from idle → must return CKR_OPERATION_NOT_INITIALIZED)
- `encrypt_final_without_init` (from idle → must return CKR_OPERATION_NOT_INITIALIZED)
- `cross_contamination` (start encrypt, attempt sign_update → must return CKR_OPERATION_ACTIVE or NOT_INITIALIZED)

**Invariants:**
- After any CKR_OPERATION_NOT_INITIALIZED, session state is idle
- After any CKR_OPERATION_ACTIVE, original operation is still active
- Only one active operation per session at any time (except dual-function combinations)

### 5.4 Object Lifetime

The object lifetime machine tests create/use/destroy sequences.

**Rules:**
- `create_session_object` (creates an AES key, records handle)
- `create_token_object` (creates a token-persisted key, requires @destructive)
- `use_object` (perform encrypt or sign with a live handle → must succeed)
- `destroy_object` (destroys a handle, marks it dead in model)
- `use_destroyed_object` (attempt operation on dead handle → CKR_OBJECT_HANDLE_INVALID)
- `destroy_nonexistent` (double destroy → CKR_OBJECT_HANDLE_INVALID)
- `get_attribute_live` (read CKA_LABEL on live object → success)
- `get_attribute_dead` (read CKA_LABEL on destroyed handle → CKR_OBJECT_HANDLE_INVALID)
- `close_session_and_check_session_objects` (session objects gone, token objects persist)

**Invariants:**
- All session object handles are invalid after session close
- Token object handles survive across session open/close (within same C_Initialize lifecycle)
- No operation succeeds on a destroyed handle

### 5.5 Cross-Session Object Visibility

| Rule | Expected behavior |
|------|-------------------|
| Session object created in session A | Not visible from session B |
| Token object created in session A | Visible from session B |
| Private object before login | Not visible in public session B |
| Private object after login | Visible in logged-in session B |
| Object destroyed in session A | Handle invalid in session B |

The `RuleBasedStateMachine` opens two simultaneous sessions and verifies
cross-session invariants after each mutation.

**Implementation note:** The state machines run in-process (same subprocess), sharing
a single C_Initialize lifecycle. The hypothesis stateful framework generates sequences
up to `max_examples=200` rule chains per test, with `settings(max_examples=200,
stateful_step_count=30)`.

Estimated: ~15 state machine tests (each runs hundreds of generated sequences).

## 6. Differential Testing (`test_differential.py`)

Run the same PKCS#11 operation against multiple backends (SoftHSM2, Kryoptic, NSS
softoken) and assert that results are cryptographically consistent. Differences are
security findings.

**Parametrize over backends:** The test is marked to run only when multiple backends
are configured. In CI, the Docker matrix provides one backend per container; differential
tests require the multi-backend fixture that reads results from a shared artifact store
or runs sequentially if multiple modules are specified.

| Operation | Assertion |
|-----------|-----------|
| AES-CBC encrypt (same key + IV) | Ciphertext identical across all backends |
| AES-GCM encrypt (same key + IV + AAD) | Ciphertext + tag identical |
| SHA-256 digest | Output identical |
| HMAC-SHA256 | Output identical |
| RSA-2048 sign (RSA-PKCS, deterministic padding) | Signature identical |
| ECDSA sign (deterministic, RFC 6979) | If deterministic, r+s identical; if not, `cryptography` cross-verify each independently |
| RSA-OAEP decrypt (known ciphertext) | Recovered plaintext identical |
| AES-KW unwrap (known wrapped key) | Recovered key material identical |
| ML-KEM encapsulate (same keypair + randomness) | If derandomized test vector, output identical |
| Public key export encoding | DER encoding identical across backends |

**Configuration:** Differential testing backends are declared in `p11test.toml`:

```toml
# p11test.toml
[differential]
modules = [
    { name = "softhsm2", path = "/usr/lib/softhsm/libsofthsm2.so", pin = "1234", env = { SOFTHSM2_CONF = "/tmp/softhsm2.conf" } },
    { name = "kryoptic", path = "/usr/lib/libkryoptic_pkcs11.so", pin = "1234" },
]
```

**CLI:** `p11test test --differential --module-config p11test.toml` or
`pytest --p11-differential`

**Results:** Per-test matrix showing pass/fail per backend; disagreements between
backends are flagged as findings.

**Reporting:** Divergence between backends is logged as `SECURITY` finding_level (it
could indicate a backend computing incorrectly or using different algorithm variants).

Estimated: ~20 tests.

## 7. Metamorphic Testing (`test_metamorphic.py`)

Metamorphic relations assert that certain transformations of inputs must produce
predictable transformations of outputs, even when the oracle is not known in advance.

### 7.1 Single-Shot vs Multi-Part Equivalence

For every multi-part mechanism, the output of the single-shot call must equal
the assembled output of the multi-part sequence for the same key and input.

| Operation | Single-shot | Multi-part | Property |
|-----------|-------------|------------|----------|
| AES-CBC encrypt | C_Encrypt(key, pt) | C_EncryptUpdate × N + C_EncryptFinal | must produce same ciphertext |
| AES-GCM encrypt | C_Encrypt | EncryptUpdate × N + Final | same ct + tag |
| SHA-256 digest | C_Digest | DigestUpdate × N + Final | same digest |
| HMAC | C_Sign (single) | SignUpdate × N + Final | same MAC |
| RSA sign (prehash mode) | C_Sign | SignUpdate × N + Final | same signature (if deterministic) |

For each mechanism, hypothesis generates random plaintext lengths and chunk
boundaries. Assert identity regardless of chunking.

### 7.2 Copy-vs-Original Equivalence

A copied key must behave identically to the original for cryptographic operations.

| Test | Description |
|------|-------------|
| AES copy encrypt equivalence | Copy AES key → encrypt same plaintext with original and copy → ciphertexts must match |
| ECDSA copy sign equivalence | Copy ECDSA key → sign same message → independently verify both signatures → both valid |
| Attribute preservation | Copy → read all attributes → assert all non-session-specific attributes match |
| Copy then destroy original | Original destroyed → copy still usable → outputs still correct |

### 7.3 Wrap→Unwrap Identity

Wrap a key, then unwrap it, then use the unwrapped key — the key material must be
preserved exactly.

| Test | Description |
|------|-------------|
| AES-KW round-trip | Wrap AES key → unwrap → encrypt with unwrapped key → decrypt with original → compare plaintext |
| RSA-OAEP wrap round-trip | Same pattern |
| AES-GCM wrap round-trip | Same pattern |
| WrapKeyAuthenticated round-trip | Same with v3.2 authenticated wrap |
| Key extraction round-trip (if extractable) | Wrap → unwrap → export value → compare to original export |

### 7.4 Encrypt→Decrypt Identity (all mechanisms)

Hypothesis generates random plaintexts and keys. Assert that
`decrypt(key, encrypt(key, pt)) == pt` for every supported mechanism.
This is the fundamental correctness metamorphic relation.

Estimated: ~25 tests (each hypothesis test generates 100+ random cases).

## 8. Crash and Fault Injection (`test_fault.py`)

Using the crash-test stub module (a minimal .so from Phase 2 of base design spec
Section 10) that is configurable to crash or hang on specific function calls.

### 8.1 Worker Kill Mid-Operation

| Test | Description |
|------|-------------|
| Kill worker during C_Encrypt | Worker subprocess killed via SIGKILL mid-C_Encrypt → outcome: `crashed`, main process recovers |
| Kill worker during C_GenerateKeyPair | Same |
| Kill worker during C_WrapKey | Same |
| Kill worker during RSA keygen (slow) | SIGKILL after 100ms → timeout handling correct |
| Kill worker during C_Initialize | Module never initialized → `crashed` |
| Kill worker during C_Finalize | Module not finalized cleanly → main process handles |

### 8.2 Hang Detection and Timeout

| Test | Description |
|------|-------------|
| Worker hangs during C_Encrypt | Stub hangs → timeout fires → marked as `timeout` |
| Worker hangs during C_Login | Same |
| Per-test timeout respected | Test exceeds `timeout_test` (default 120s) → killed |
| Per-operation timeout respected | Single C_* call exceeds `timeout_operation` (default 30s) → killed |
| Global timeout | All tests exceed global budget → remaining marked `timeout` |

### 8.3 Recovery Verification

After any crash or timeout, verify that the test runner (main process) remains
functional and can successfully execute subsequent tests:

| Test | Description |
|------|-------------|
| Post-crash next test passes | Crash test followed by known-good test → good test passes |
| Post-timeout next test passes | Timeout test followed by known-good test → good test passes |
| Multiple crashes, counters correct | 5 crash tests → 5 counted, runner continues |
| Result queue not corrupted | Crashed worker queue entry is clean error, no partial data |

### 8.4 SIGSEGV Segfault Survival

| Test | Description |
|------|-------------|
| SIGSEGV in stub C_Sign | Worker takes SIGSEGV → outcome is `crashed (signal 11)` |
| SIGSEGV in stub C_GetAttributeValue | Same |
| SIGSEGV during token enumeration | Worker crashes during slot list → handled |

Estimated: ~25 tests (requires crash-test stub module; skipped if stub unavailable).

## 9. Interoperability Testing (`test_interop.py`)

Tests import/export paths using externally-encoded key material and certificates,
and verify that p11test correctly handles encoding variants and malformed inputs.

### 9.1 Encoding Corpora

The following corpora of pre-generated blobs are stored in
`src/p11test/testcases/vectors/encoding/`:

**Malformed DER/SPKI:**
- Truncated DER (cut at various byte offsets)
- Extra trailing bytes after valid DER
- Zero-length sequence
- Length field overflow (claimed length > actual data)
- Non-canonical length encoding (long form where short form required)
- Nested sequence depth > 64 (stack overflow attempt)

**Malformed PKCS#8 private keys:**
- Missing version field
- Wrong algorithm OID
- Inner key data truncated
- EC private key with point not on curve
- RSA key with p*q ≠ n

**Malformed X.509 certificates:**
- Expired validity (NotAfter in the past)
- Invalid signature bytes
- Critical extension not understood
- Subject and Issuer swapped
- Serial number negative (BER-valid but DER-invalid)

**Non-canonical ECDSA DER signatures:**
- High-S signature (s > n/2, valid but non-normalized)
- Leading zero byte in r or s (over-padded)
- Missing leading zero on r when MSB set
- Short-form r,s (truncated to fewer bytes)
- r = 0 or s = 0 (degenerate)
- Signature length ≠ sum of r,s lengths

**RSA PKCS#1 v1.5 BER laxness:**
- Padding bytes with non-zero value
- PS shorter than 8 bytes
- No 0x00 separator before message
- Type byte 0x02 instead of 0x01 (wrong block type)

**EC point encoding variants:**
- Compressed (0x02, 0x03 prefix)
- Uncompressed (0x04 prefix) — the standard
- Hybrid (0x06, 0x07 prefix) — valid in some standards
- Point at infinity encoding
- Invalid prefix byte (0x05)
- Compressed point where module expects uncompressed

### 9.2 Import Tests

For each malformed encoding category:

| Test | Expected behavior |
|------|-------------------|
| C_CreateObject with malformed SPKI | Must return CKR_ATTRIBUTE_VALUE_INVALID or similar |
| C_CreateObject with truncated PKCS#8 | Must fail, no partial object created |
| C_CreateObject with high-S ECDSA key | Module may accept or reject; if accepted, verify sign/verify still works |
| C_CreateObject with compressed EC point | Module may accept or reject; if accepted, operations correct |
| C_CreateObject with hybrid EC point | Same |
| C_CreateObject with malformed X.509 cert | Module may be lenient; record behavior |

### 9.3 Protocol Suite Compatibility

| Test | Description |
|------|-------------|
| TLS-like signing | Sign ServerKeyExchange structure → verify |
| CMS/PKCS#7 signing | Sign CMS → verify with `cryptography` |
| CSR generation (PKCS#10) | Sign CSR → parse and verify |
| X.509 self-signed cert | Self-sign certificate → verify chain |
| JWT signing | Sign JWT payload → verify with public key |

### 9.4 Encoding Variant Acceptance

For valid-but-unusual encodings (compressed EC points, high-S ECDSA), record
whether the module accepts or rejects them. This is informational — there is no
single correct behavior, but inconsistency within the same module is a finding.

Estimated: ~40 tests.

## 10. Run Profiles

Named profiles allow operators to select the appropriate test scope for their
use case without manually specifying marker combinations.

### 10.1 Profile Definitions

| Profile | Included markers | Excluded markers | Target count | Target time |
|---------|-----------------|-----------------|-------------|-------------|
| `smoke` | (tests not marked with any slow/special marker) | fuzz, benchmark, stress, timing, wycheproof, security, destructive, padding_oracle, nonce_quality, regressions, surface_audit, vendor, stateful, differential, metamorphic, fault, boundary | ~50 | <30s |
| `full` | crossverify, kat, wycheproof, keymgmt, multipart, access, search, mechflags, protocol, interop, v30, v32 | benchmark, stress, timing, fuzz, destructive | ~1,400+ | <10m |
| `security` | security, padding_oracle, nonce_quality, timing, regressions | benchmark, stress, fuzz, destructive | ~100 | <5m |
| `lab` | (all) | none | ~2,400+ | variable |
| `fips` | kat, fips, crossverify | (non-FIPS algorithms) | ~80 | <2m |
| `v32` | requires_v32 | none | ~80 | <3m |
| `hardware` | correctness, crossverify, kat, wycheproof, keymgmt, access, protocol | destructive, stress, fuzz, timing, surface_audit, benchmark | ~300 | <15m |
| `stateful` | stateful | none | ~15 | <5m |
| `differential` | differential | none | ~20 | variable |

### 10.2 Implementation

**As pytest marks:** Each profile is implemented as a pytest mark and a
`--profile` CLI option that translates to the corresponding `-m` expression.

```python
# pytest.ini marks
pytest.ini_options.markers = [
    "smoke: quick sanity check subset",
    "full: all correctness tests",
    "security: security attack vector tests",
    "lab: everything including timing, stress, fuzz",
    "fips: FIPS-relevant subset",
    "v32: v3.2-specific tests only",
    "hardware: safe for real HSMs, no destructive or stress",
    "stateful: hypothesis state machine tests",
    "differential: cross-backend differential tests",
]
```

**As CLI option:**

```
p11test test --profile smoke      # equivalent to: pytest -m "not (fuzz or benchmark or stress or timing or wycheproof or security or destructive)"
p11test test --profile full       # equivalent to: pytest -m "not (benchmark or stress or timing or fuzz or destructive)"
p11test test --profile security   # security-focused subset
p11test test --profile lab        # everything
p11test test --profile hardware   # HSM-safe subset (excludes destructive, stress, fuzz, timing, surface_audit, benchmark)
```

Note on `hardware` profile: `surface_audit` is excluded because it brute-forces
mechanism/slot/handle spaces which may trigger rate limits, alerts, or lockouts on
real HSMs. The `hardware` profile is safe for production hardware and covers
correctness, crossverify, kat, wycheproof, keymgmt, access (read-only attribute
checks only), and protocol tests.

The `--profile` flag can be combined with `--match` and `--category` for further
filtering. `--profile lab` is required before any `--stress`, `--fuzz`, or `--benchmark`
tests run.

### 10.3 Required CKR_ Result Sets per Category

For `"invalid"` Wycheproof vectors and other negative-test scenarios, the following
error codes are the ONLY acceptable returns (anything else is a test FAIL):

| Category | Allowed CKR_ error codes |
|----------|--------------------------|
| Decrypt (bad ciphertext) | `CKR_ENCRYPTED_DATA_INVALID`, `CKR_ENCRYPTED_DATA_LEN_RANGE` |
| Decrypt (bad tag, AEAD) | `CKR_ENCRYPTED_DATA_INVALID` |
| Verify (bad signature) | `CKR_SIGNATURE_INVALID`, `CKR_SIGNATURE_LEN_RANGE` |
| Unwrap (bad wrapped key) | `CKR_WRAPPED_KEY_INVALID`, `CKR_WRAPPED_KEY_LEN_RANGE`, `CKR_ENCRYPTED_DATA_INVALID` |
| DecapsulateKey (bad ciphertext) | `CKR_ENCRYPTED_DATA_INVALID` |
| Import bad key material | `CKR_ATTRIBUTE_VALUE_INVALID`, `CKR_TEMPLATE_INCONSISTENT` |
| Mechanism parameter error | `CKR_MECHANISM_PARAM_INVALID` |

Any other CKR_ value for these categories is recorded as a FAIL. The test also
asserts that the session is still usable and no unwanted object was created.

## 11. Statistical Test Methodology

Statistical tests (timing, nonce bias, RNG quality) are opt-in and require careful
configuration to produce meaningful results. These tests are **sanity checks, not
certifications** — they can surface obvious flaws but cannot certify cryptographic
quality to FIPS 140-3 or NIST SP 800-22 standards.

### 11.1 Configuration Parameters

All statistical tests read from a `[statistics]` section in `p11test.toml`:

```toml
[statistics]
warmup_rounds = 50          # discard first N samples (JIT, caching effects)
sample_size = 1000          # default sample count
lab_sample_size = 10000     # sample count in --profile lab mode
significance_threshold = 0.001  # p-value threshold for timing t-tests
rng_chi2_significance = 0.01    # chi-squared p-value threshold for RNG tests
```

### 11.2 Warmup Rounds

Before collecting samples, all statistical tests discard the first `warmup_rounds`
measurements. This accounts for JIT compilation, CPU frequency scaling, TLB priming,
and PKCS#11 module internal caches.

### 11.3 Host Metadata Recording

Every statistical test result includes:
```json
{
  "cpu_model": "Intel Core i9-13900K",
  "cpu_count": 24,
  "os": "Linux 6.17.0",
  "python_version": "3.11.9",
  "module_path": "/usr/lib/softhsm/libsofthsm2.so",
  "module_version": "2.6.1",
  "sample_size": 1000,
  "warmup_rounds": 50,
  "timestamp": "2026-03-16T12:00:00Z"
}
```

This is stored in the machine-readable evidence field of the test result (see
Section 13.2) so that results can be compared across devices and over time.

### 11.4 Per-Device Baseline Support

Operators can record a baseline run:
```
p11test test --profile lab --save-baseline baseline-2026-03-16.json
```

Subsequent runs compare against the baseline:
```
p11test test --compare-baseline baseline-2026-03-16.json
```

Timing regressions (>2σ change from baseline) are flagged as `WARNING`.
Timing improvements are informational.

### 11.5 scipy Dependency

Statistical tests require `scipy` for Welch's t-test, chi-squared, and runs test:

```toml
[project.optional-dependencies]
stats = [
    "scipy>=1.12",
]
```

Statistical tests are skipped with a `SKIP (scipy not installed)` message if
scipy is unavailable. Install with: `pip install p11test[stats]`.

### 11.6 Explicit Disclaimer

Every statistical test result includes in its `INFO` output:

> "This is a sanity check for obvious implementation flaws, not a certification.
> Results depend on the test host, load, and sample size. Passing these tests does
> not imply FIPS 140-3, NIST SP 800-22, or AIS-31 compliance."

## 12. Robustness Testing

### 12.1 Fuzz Testing (`test_fuzz.py`)

Using `hypothesis` for property-based testing:

| Category | Strategy |
|----------|----------|
| Input fuzzing | Random plaintext sizes (0–64KB), random IVs, random AAD |
| Parameter fuzzing | Random mechanism parameters, boundary key sizes |
| Sequence fuzzing | Random ordering of Init/Update/Final calls |
| Attribute fuzzing | Random attribute templates for C_CreateObject |

**Property being tested:** operation either succeeds correctly or returns a valid CKR_ error.
Must NEVER crash, hang, or corrupt state.

Estimated: ~20 property tests (each runs 100+ examples by default).

### 12.2 Memory & Resource Safety (`test_resource.py`)

| Test | Description |
|------|-------------|
| Key generation leak | 10,000 keys → RSS growth < 10MB |
| Session open/close leak | 10,000 cycles → RSS stable |
| Encrypt cycle leak | 10,000 encrypt/decrypt → RSS stable |
| Handle exhaustion | Create objects until failure → clean error |
| Session exhaustion | Open sessions until CKR_SESSION_COUNT |
| Orphaned operation | EncryptInit → new EncryptInit → must cancel or error |
| Double destroy | C_DestroyObject twice → clean error, no crash |
| Use-after-destroy | Encrypt with destroyed handle → clean error |
| C_Finalize with open sessions | Must close all cleanly |
| Rapid init/finalize | 1,000 C_Initialize/C_Finalize cycles → no leak |

Estimated: ~15 tests.

### 12.3 RNG Quality (`test_rng.py`)

These tests use configurable sample sizes (see Section 11.1) and include warmup.

| Test | Description |
|------|-------------|
| Non-zero | 1KB → not all zeros |
| Non-repeating | 1000 × 32B → all unique |
| Bit frequency | Chi-squared on 100KB |
| Runs test | NIST SP 800-22 basic frequency |
| Monobit test | Frequency of 0s vs 1s within tolerance |

Estimated: ~5 tests.

### 12.4 Boundary Suites (`test_boundary.py`)

Tests that probe the limits of PKCS#11 object and operation parameters.
Marked `@pytest.mark.boundary`.

| Test | Description |
|------|-------------|
| Maximum label length (32 bytes) | Create object with 32-byte CKA_LABEL → succeeds, read back matches |
| Maximum label length (256 bytes) | Create object with 256-byte CKA_LABEL → succeeds or CKR_ATTRIBUTE_VALUE_INVALID |
| Maximum label length (module max) | Probe module's actual label limit; record result |
| Maximum attribute template size | C_FindObjectsInit with 100-attribute template → succeeds or CKR_TEMPLATE_INCONSISTENT |
| Maximum wrapped blob size | Wrap the largest possible key (RSA-4096 private key) → verify unwrap round-trip |
| Very large multipart stream | C_EncryptUpdate in 64KB chunks for 100MB total → output matches single-shot |
| Maximum object count | Create objects until CKR_DEVICE_MEMORY or module limit → verify clean error, no crash |

Estimated: ~10 tests.

## 13. Performance Testing

### 13.1 Benchmarks (`test_benchmark.py`)

Using `pytest-benchmark`:

| Benchmark | Parameters |
|-----------|-----------|
| AES-256-CBC encrypt | 1KB, 4KB, 64KB, 1MB payloads |
| AES-256-GCM encrypt | same |
| RSA-2048 sign | per-operation |
| RSA-4096 sign | per-operation |
| ECDSA P-256 sign | per-operation |
| ECDSA P-384 sign | per-operation |
| SHA-256 digest | 1KB, 64KB, 1MB |
| Key generation (AES-256) | per-operation |
| Key generation (RSA-2048) | per-operation |
| Key generation (EC P-256) | per-operation |
| Session open/close | per-cycle |

Metrics: ops/sec, min/max/mean/median latency, stddev.

Estimated: ~25 benchmark tests.

### 13.2 Concurrency & Stress (`test_stress.py`)

| Test | Description |
|------|-------------|
| N sessions, 1 op each | 10, 50, 100 concurrent sessions |
| 1 session, N ops | 10,000 sign operations → detect leaks |
| N sessions parallel | ThreadPoolExecutor, concurrent operations |
| Session churn | 1,000 rapid open/close cycles |
| Thread per session | Each thread owns a session → independent ops |
| Shared session (forbidden) | Two threads share session → verify rejection |
| Resource exhaustion | Open sessions until limit → clean error |
| Long-running stability | 60s continuous ops → memory stable (psutil) |

Estimated: ~15 tests.

## 14. Surface Audit & Hidden Capability Probing (`test_surface_audit.py`)

Systematically probe the PKCS#11 module's entire API surface for undocumented,
hidden, or inconsistent capabilities. This catches debug mechanisms left in
production, backdoors, incomplete decommissioning, and access control gaps.

### 14.1 Hidden Mechanism Probing

| Test | Technique |
|------|-----------|
| Scan all standard mechanisms | Probe `C_GetMechanismInfo` for all ~600 CKM_ IDs (0x0000–0x1FFF) → flag any that respond but aren't in `C_GetMechanismList` |
| Scan vendor ranges | Probe known vendor offsets (0x80000000+, 0xCE534350+, 0xD9554200+, 0xDE436972+) → flag hidden vendor mechanisms |
| Disabled-but-accessible | For every non-advertised mechanism, try `C_EncryptInit`/`C_SignInit` with valid key → flag any that don't return `CKR_MECHANISM_INVALID` |
| Deprecated mechanisms | If module claims v3.0+, verify deprecated mechanisms (DES, MD2) are truly disabled |

### 14.2 Hidden Slot & Object Probing

| Test | Technique |
|------|-----------|
| Shadow slots | Probe slot IDs 0–255 with `C_GetSlotInfo` → flag any beyond `C_GetSlotList` results |
| Hidden attributes | Call `C_GetAttributeValue` for all ~120 CKA_ IDs on each key → flag unexpected/vendor attributes |
| Hidden object classes | Search with each CKO_ value + `CKO_VENDOR_DEFINED` offsets → flag undocumented objects |
| Hidden key types | Try `C_GenerateKey` with unusual CKK_ values → flag any that unexpectedly succeed |

### 14.3 Interface & Function Probing (v3.x)

| Test | Technique |
|------|-----------|
| Hidden interfaces | `C_GetInterface` with non-standard names ("DEBUG", "ADMIN", etc.) → flag any that respond |
| NULL function pointers | In v3.x function list, check every function pointer → flag NULL pointers for supposedly supported functions |
| All C_* functions callable | Call every PKCS#11 function → must return valid CKR_ code or CKR_FUNCTION_NOT_SUPPORTED, NEVER crash |
| Hidden v3.x functions | If module reports v2.40, probe v3.0/v3.2 functions via ctypes → verify they fail cleanly |

### 14.4 Access Control Probing

| Test | Technique |
|------|-----------|
| PIN bypass | Try crypto operations without login when login should be required |
| Empty PIN | `C_Login` with empty string and NULL → should fail cleanly |
| SO privilege escalation | SO session attempts user crypto operations → must fail |
| User privilege escalation | User session attempts SO-only operations (C_InitPIN) → must fail |
| Cross-slot handles | Use object handle from slot A in operations on slot B → must fail cleanly |
| Cross-session handles | Use object handle from session A in different-user session B → must fail |
| Handle prediction | Generate 100 objects → check if handles are sequential (security concern: predictable handles aid attacks) |
| Post-logout access | Logout → attempt operation with previously-valid handle → must fail |

### 14.5 Token Info Audit

| Test | Technique |
|------|-----------|
| Vendor flag bits | Check `CK_TOKEN_INFO.flags` for vendor-defined bits (0x80000000+) → report any set |
| Hardware/firmware version | Log and validate version fields are within reasonable ranges |
| Serial number format | Verify CK_TOKEN_INFO.serialNumber is valid |
| Free space tracking | Check `ulFreePublicMemory`/`ulFreePrivateMemory` before and after key creation → verify it decrements |
| Label consistency | Set label → read back → must match exactly (no truncation, encoding issues) |

Estimated: ~50 tests. All results are SECURITY or INFO level — these are audit findings.

## 15. Compliance Testing

### 14.1 FIPS 140-3 Checks (`test_fips.py`)

| Test | Description |
|------|-------------|
| Power-on self-test | C_Initialize succeeds (implies self-tests passed) |
| FIPS mode detection | Check CKF_FIPS_APPROVED flag if available |
| Approved algorithms only | In FIPS mode, MD5/DES should be unavailable |
| Zeroization | After C_Finalize, old handles must fail |

Estimated: ~5 tests.

### 14.2 Protocol Integration (`test_protocol.py`)

| Test | Description |
|------|-------------|
| TLS-like signing | Sign ServerKeyExchange structure → verify |
| CMS/PKCS#7 signing | Sign CMS → verify with `cryptography` |
| CSR generation (PKCS#10) | Sign CSR → parse and verify |
| X.509 self-signed cert | Self-sign certificate → verify chain |
| JWT signing | Sign JWT payload → verify with public key |

Estimated: ~10 tests.

## 16. Vendor Mechanism Extensibility

p11test must be extensible for vendor-specific mechanisms (CKM_VENDOR_DEFINED + offset)
without modifying core test code. This is critical because real-world HSMs expose 70+
vendor mechanisms across 8+ vendors.

### 15.1 Architecture: TOML-Based Vendor Profiles

Vendor mechanisms and their parameters are defined in TOML files:

```
src/p11test/
├── vendors/
│   ├── __init__.py
│   ├── registry.py            # loads TOML profiles, registers mechanisms
│   ├── profiles/              # TOML vendor profiles
│   │   ├── aws-cloudhsm.toml
│   │   ├── thales-luna.toml
│   │   ├── ibm-ep11.toml
│   │   ├── yubico-yubihsm.toml
│   │   ├── entrust-nshield.toml
│   │   ├── google-cloudkms.toml
│   │   ├── mozilla-nss.toml
│   │   └── russian-gost.toml
│   └── test_vendor.py         # parametrized vendor mechanism tests
```

### 15.2 Vendor Profile Format

```toml
[vendor]
name = "AWS CloudHSM"
base = 0x80000000
reference = "cloudhsm_pkcs11_vendor_defs.h"

[[mechanisms]]
name = "CKM_CLOUDHSM_AES_GCM"
value = 0x80001087
params = "gcm"
operations = ["encrypt", "decrypt"]
key_types = ["AES"]
key_sizes = [128, 256]
description = "AES-GCM with HSM-generated IV"

[[mechanisms]]
name = "CKM_CLOUDHSM_SP800_108_COUNTER_KDF"
value = 0x80000001
params = "sp800_108_kdf"
operations = ["derive"]
key_types = ["GENERIC_SECRET"]
description = "SP800-108 Counter KDF"
```

### 15.3 Known Vendor Mechanisms (from pkcs11-proxy research)

**8 vendors, 71 mechanisms:**

| Vendor | Count | Key mechanisms |
|--------|-------|---------------|
| AWS CloudHSM | 5 | AES-GCM (HSM-IV), AES key wrap variants, SP800-108 KDF, X9.63 KDFs |
| Thales Luna | 20+ | SEED, ARIA, KCDSA (Korean), ECIES, DUKPT, EdDSA (pre-std), object cloning |
| IBM EP11 | 12+ | SHA-3 family, Dilithium/ML-DSA, Kyber/ML-KEM, BTC/ETH derivation, Schnorr |
| Yubico YubiHSM | 2 | AES-CCM wrap, RSA wrap |
| Entrust nShield | 8 | AES-CMAC, ECIES, HMAC key generation |
| Mozilla NSS | 10+ | HKDF, PBE, AES key wrap, TLS PRF |
| Google Cloud KMS | 1 | AES-GCM (HSM-IV) |
| Russian GOST/TC26 | 6 | GOST R 34.10/34.11-2012, key derivation, key wrapping |

### 15.4 Vendor Test Strategy

**CLI usage:**
```bash
p11test test --module /path/to.so --vendor aws-cloudhsm --pin 1234
p11test test --module /path/to.so --vendor-profile custom-vendor.toml
```

**Automatic detection:** If `--vendor` is not specified, p11test queries `C_GetMechanismList`
and matches mechanism IDs against known vendor profiles.

**Test generation per vendor mechanism:**

For each vendor mechanism, generate tests based on `operations`:
- `encrypt`/`decrypt` → round-trip test with cross-verification if possible
- `sign`/`verify` → sign + verify round-trip
- `derive` → derive shared secret, verify determinism
- `wrap`/`unwrap` → wrap + unwrap round-trip, verify key material preserved
- `keygen` → generate key, verify attributes
- `digest` → digest with known input, verify output size
- `mac` → MAC with known key, verify output

**Parameter fuzzing per vendor mechanism:**
For mechanisms with complex parameters (GCM, KDF, ECIES), generate hypothesis
strategies from the TOML `params` specification.

### 15.5 Vendor Cross-Verification

Where possible, cross-verify vendor mechanisms against known implementations:
- IBM SHA-3 → `hashlib` SHA-3 (Python 3.6+)
- IBM Dilithium/Kyber → `liboqs-python` or NIST reference vectors
- Luna SEED/ARIA → `cryptography` (if supported) or known test vectors
- GOST → `pygost` or `gostcrypto` libraries
- NSS HKDF → `cryptography` HKDF

### 15.6 User-Defined Vendor Profiles

Users can create custom `.toml` profiles for unsupported HSMs:
```bash
# Create custom profile
p11test vendor-init --module /path/to.so --output my-hsm.toml
# Auto-discovers vendor mechanisms via C_GetMechanismList
# User fills in parameter types and test expectations

# Run with custom profile
p11test test --vendor-profile my-hsm.toml --module /path/to.so
```

Estimated: ~30 base tests per vendor profile × 8 vendors = ~240 vendor tests.

## 17. Test File Organization

```
src/p11test/testcases/
├── vectors/                    # Static test vector data
│   ├── nist/                   # NIST CAVP vectors (JSON)
│   │   ├── aes_cbc.json
│   │   ├── aes_ofb.json
│   │   ├── aes_cfb.json
│   │   ├── aes_gcm.json
│   │   ├── sha256.json
│   │   ├── ml_kem_768.json
│   │   ├── ml_dsa_65.json
│   │   ├── slh_dsa_shake_128s.json
│   │   └── ...
│   ├── wycheproof/             # Wycheproof vectors (JSON, git submodule or vendored)
│   │   ├── aes_gcm_test.json
│   │   ├── ecdsa_secp256r1_sha256_test.json
│   │   └── ...
│   ├── rfc/                    # RFC test vectors
│   │   ├── rfc3394_aes_kw.json
│   │   └── rfc5649_aes_kwp.json
│   └── encoding/               # Malformed encoding corpora
│       ├── malformed_der/
│       ├── malformed_pkcs8/
│       ├── malformed_x509/
│       ├── noncanonical_ecdsa/
│       └── ec_point_variants/
├── conftest.py                 # Shared fixtures, vector loader
├── test_interface.py           # existing
├── test_slot.py                # existing
├── test_object.py              # existing, expanded
├── test_mechanism.py           # existing, expanded
├── test_encrypt.py             # existing, expanded with all symmetric ciphers incl. OFB/CFB
├── test_sign.py                # existing, expanded with all asymmetric sign/verify
├── test_digest.py              # existing, expanded
├── test_errors.py              # existing, expanded (Galois-style)
├── test_crossverify.py         # NEW: cross-verification with `cryptography`
├── test_kat.py                 # NEW: NIST known-answer tests (incl. PQC KAT vectors)
├── test_wycheproof.py          # NEW: Wycheproof edge-case vectors
├── test_keymgmt.py             # NEW: import, export, wrap, unwrap, derive
├── test_multipart.py           # NEW: multi-part + dual-function
├── test_access.py              # NEW: attribute enforcement, session types
├── test_token.py               # NEW: @destructive — InitToken, PIN mgmt
├── test_search.py              # NEW: object search & enumeration
├── test_mechflags.py           # NEW: mechanism flags validation
├── test_api_security.py        # NEW: PKCS#11 policy abuse, attribute laundering
├── test_padding_oracle.py      # NEW: Bleichenbacher/Vaudenay detection
├── test_nonce_quality.py       # NEW: ECDSA nonce analysis
├── test_timing.py              # NEW: timing side-channel detection
├── test_regressions.py         # NEW: known CVE regression tests
├── test_fuzz.py                # NEW: hypothesis property tests
├── test_resource.py            # NEW: memory/handle leak detection
├── test_rng.py                 # NEW: RNG quality
├── test_benchmark.py           # NEW: pytest-benchmark performance
├── test_stress.py              # NEW: concurrency/multi-session stress
├── test_fips.py                # NEW: FIPS 140-3 compliance checks
├── test_protocol.py            # NEW: TLS/CMS/X.509/JWT integration
├── test_interop.py             # NEW: encoding corpora, malformed input, protocol suites
├── test_message.py             # NEW: v3.0 message-based operations
├── test_async.py               # NEW: v3.2 async operations
├── test_pqc.py                 # NEW: ML-KEM, ML-DSA, SLH-DSA with KAT vectors
├── test_authwrap.py            # NEW: v3.2 authenticated wrap/unwrap with tamper cases
├── test_profiles.py            # NEW: CKO_PROFILE objects, profile conformance
├── test_session_validation.py  # NEW: C_GetSessionValidationFlags
├── test_stateful.py            # NEW: hypothesis.stateful state machine tests
├── test_differential.py        # NEW: cross-backend differential testing
├── test_metamorphic.py         # NEW: single-shot vs multi-part, copy, wrap/unwrap identity
├── test_fault.py               # NEW: crash/fault injection (requires crash-test stub)
└── test_vendor.py              # NEW: parametrized vendor mechanism tests (from TOML profiles)
```

**Vendor mechanism profiles:**
```
src/p11test/vendors/
├── __init__.py
├── registry.py                 # TOML loader, mechanism registration, auto-detection
├── profiles/
│   ├── aws-cloudhsm.toml       # 5 mechanisms (AES-GCM HSM-IV, key wrap, SP800-108 KDF)
│   ├── thales-luna.toml        # 20+ mechanisms (SEED, ARIA, KCDSA, ECIES, DUKPT, EdDSA)
│   ├── ibm-ep11.toml           # 12+ mechanisms (SHA-3, Dilithium, Kyber, BTC/ETH derive)
│   ├── yubico-yubihsm.toml    # 2 mechanisms (AES-CCM wrap, RSA wrap)
│   ├── entrust-nshield.toml    # 8 mechanisms (AES-CMAC, ECIES, HMAC keygen)
│   ├── google-cloudkms.toml    # 1 mechanism (AES-GCM HSM-IV)
│   ├── mozilla-nss.toml        # 10+ mechanisms (HKDF, PBE, TLS PRF)
│   └── russian-gost.toml       # 6 mechanisms (GOST R 34.10/34.11-2012, key derive/wrap)
└── test_vendor.py              # Parametrized tests driven by profiles
```

## 18. New Dependencies

```toml
dependencies = [
    # existing...
    "cryptography>=44.0",       # cross-verification, interop
]

[project.optional-dependencies]
dev = [
    # existing...
    "hypothesis>=6.0",          # fuzz testing and stateful model testing
    "pytest-benchmark>=4.0",    # benchmarks
]
stats = [
    "scipy>=1.12",              # statistical tests (timing, RNG, nonce bias)
]
pqc = [
    "liboqs-python>=0.11.0",    # cross-verification for ML-KEM, ML-DSA, SLH-DSA
]
gost = [
    "pygost>=5.0",              # cross-verification for GOST R 34.10/34.11 mechanisms
]
```

Users must install relevant extras before running tests that require them:

```
pip install p11test[pqc,gost,stats]
```

Optional dependency groups:
- `dev` — development tools (hypothesis, pytest-benchmark, etc.)
- `pqc` — `liboqs-python` for PQC cross-verification (ML-KEM, ML-DSA, SLH-DSA)
- `gost` — `pygost` for GOST algorithm cross-verification
- `stats` — `scipy` for statistical tests (timing side-channel, RNG quality, nonce bias)

Tests requiring an uninstalled extra are skipped with an explanatory message
(e.g., `SKIP (liboqs-python not installed)`). No extra is installed automatically.

## 19. New Markers

```python
@pytest.mark.crossverify    # tests that verify against cryptography lib
@pytest.mark.kat            # NIST known-answer tests
@pytest.mark.wycheproof     # Wycheproof edge-case vectors
@pytest.mark.security       # security attack vector tests
@pytest.mark.fuzz           # hypothesis fuzzing (slow)
@pytest.mark.benchmark      # performance tests (slow)
@pytest.mark.stress         # resource/concurrency stress (slow)
@pytest.mark.timing         # timing side-channel (slow, informational)
@pytest.mark.stateful       # hypothesis state machine tests
@pytest.mark.differential   # cross-backend differential tests
@pytest.mark.metamorphic    # metamorphic relation tests
@pytest.mark.fault          # fault injection tests (requires crash-test stub)
@pytest.mark.destructive    # modifies token state (existing)
@pytest.mark.requires_v30   # skip if interface < 3.0 (existing)
@pytest.mark.requires_v32   # skip if interface < 3.2 (existing)
@pytest.mark.v30            # v3.0-specific tests
@pytest.mark.keymgmt        # key import, export, wrap, unwrap, derive
@pytest.mark.multipart      # multi-part and dual-function operations
@pytest.mark.access         # attribute enforcement, session type tests
@pytest.mark.search         # object search and enumeration
@pytest.mark.mechflags      # mechanism flags validation
@pytest.mark.protocol       # TLS/CMS/X.509/JWT integration tests
@pytest.mark.interop        # encoding corpora, malformed input
@pytest.mark.padding_oracle # RSA PKCS#1 v1.5 / AES-CBC padding oracle detection
@pytest.mark.nonce_quality  # ECDSA nonce bias and reuse analysis
@pytest.mark.regressions    # known CVE regression tests
@pytest.mark.surface_audit  # hidden mechanism/slot/object probing
@pytest.mark.vendor         # parametrized vendor mechanism tests
@pytest.mark.boundary       # boundary condition tests (max label, max template, etc.)
@pytest.mark.needs_mechanism("AES_GCM")  # mechanism-specific (existing)
@pytest.mark.smoke          # quick sanity subset
@pytest.mark.full           # all correctness tests
@pytest.mark.lab            # everything including timing/stress/fuzz
@pytest.mark.fips           # FIPS-relevant subset
@pytest.mark.v32            # v3.2-specific tests only
@pytest.mark.hardware       # safe for real HSMs
```

## 20. Test Result Classification

Not all failures are equal. Tests should report findings at different severity levels:

| Level | Meaning | Example |
|-------|---------|---------|
| FAIL | Incorrect behavior | AES-CBC decrypts to wrong plaintext |
| SECURITY | Security vulnerability detected | Padding oracle distinguishable errors; attribute laundering succeeds |
| WARNING | Potentially concerning | Timing difference >2σ but <3σ; unexpected CKR_ error code |
| INFO | Informational finding | Module uses deterministic ECDSA (good); compressed EC points accepted |
| SKIP | Not applicable | Mechanism not supported; interface version too low |

Implementation: Custom pytest plugin hook that annotates test results with severity.

### 18.1 --fail-on Severity Level

The `--fail-on` CLI option controls which severity levels cause a non-zero exit code:

```
p11test test --fail-on FAIL         # default: only hard failures fail the run
p11test test --fail-on SECURITY     # security findings also fail the run
p11test test --fail-on WARNING      # warnings also fail the run
```

When `--fail-on SECURITY` is set, any `SECURITY`-level finding causes exit code 1
even if all functional tests pass. This is appropriate for CI gating on HSM certification.

### 18.2 Machine-Readable Evidence Fields

Each test result in JSON output includes structured evidence fields.

Schema notes:
- `outcome` = the pytest outcome (`passed`/`failed`/`skipped`/`error`). Always
  reflects the test assertion: a test that checks for a vulnerability and finds the
  module is safe → `outcome: "passed"`. A test that detects a vulnerability →
  `outcome: "failed"`.
- `finding_level` = the security significance (`SECURITY`/`WARNING`/`INFO`/`null`).
  A passing test has `finding_level: null`. A failing test that detected a security
  vulnerability has `finding_level: "SECURITY"`.

Example — module prevented the attack (test passes, no finding):

```json
{
  "test_id": "test_api_security::test_wrap_decrypt_oracle",
  "outcome": "passed",
  "finding_level": null,
  "duration_s": 0.423,
  "pkcs11_rc": 0,
  "evidence": {
    "attack": "wrap-decrypt oracle",
    "key_handle": 12,
    "wrap_mechanism": "CKM_AES_KEY_WRAP",
    "decrypt_mechanism": "CKM_AES_CBC",
    "result": "module_prevented",
    "vector_source": null
  },
  "vector_manifest": null
}
```

Example — vulnerability detected (test fails, security finding):

```json
{
  "test_id": "test_api_security::test_wrap_decrypt_oracle",
  "outcome": "failed",
  "finding_level": "SECURITY",
  "duration_s": 0.401,
  "pkcs11_rc": 0,
  "evidence": {
    "attack": "wrap-decrypt oracle",
    "key_handle": 12,
    "wrap_mechanism": "CKM_AES_KEY_WRAP",
    "decrypt_mechanism": "CKM_AES_CBC",
    "result": "key_extracted",
    "vector_source": null
  },
  "vector_manifest": null
}
```

For KAT and Wycheproof tests, `vector_manifest` contains:

```json
{
  "source": "wycheproof",
  "file": "aes_gcm_test.json",
  "commit": "2196000",
  "hash_sha256": "a3f1c2...",
  "test_id": 42,
  "flags": ["InvalidTag"]
}
```

The commit and hash pin the exact vector set used, enabling reproducible audit trails.
Vector manifest files are stored in `src/p11test/testcases/vectors/manifests/`.

## 21. Phasing

### Phase 2a — Cross-Verification & Mechanism Coverage (first)
- `test_crossverify.py` — ~55 tests
- `test_kat.py` — ~60 tests (incl. PQC KAT)
- `test_keymgmt.py` — ~25 tests
- `test_multipart.py` — ~20 tests
- Expand existing test files with parameter matrices (incl. AES-OFB, AES-CFB)
- Add `cryptography` dependency

### Phase 2b — Wycheproof Vectors
- `test_wycheproof.py` — ~1,200 parametrized tests
- Vector loader infrastructure with pinned manifests
- Wycheproof JSON files (vendored or submodule)
- Tightened invalid-vector CKR_ assertions

### Phase 2c — Security Testing
- `test_api_security.py` — attribute laundering, login invalidation, state abuse
- `test_padding_oracle.py` — error oracle detection
- `test_nonce_quality.py` — ECDSA nonce analysis
- `test_timing.py` — timing side-channels (requires `stats` extra)
- `test_regressions.py` — known CVE checks
- `--fail-on` severity option

### Phase 2d — v3.x Testing
- `test_message.py` — v3.0 message-based operations
- `test_async.py` — v3.2 async operations
- `test_pqc.py` — ML-KEM, ML-DSA, SLH-DSA with KAT vectors
- `test_authwrap.py` — v3.2 authenticated wrap/unwrap
- `test_profiles.py` — CKO_PROFILE objects
- `test_session_validation.py` — C_GetSessionValidationFlags

### Phase 2e — Model-Based & Advanced Testing
- `test_stateful.py` — hypothesis state machine tests
- `test_differential.py` — cross-backend differential testing
- `test_metamorphic.py` — metamorphic relation tests
- `test_fault.py` — crash/fault injection (requires crash-test stub)

### Phase 2f — Vendor Mechanism Testing
- `src/p11test/vendors/` — TOML profiles for 8 vendors (71 mechanisms)
- `test_vendor.py` — parametrized vendor mechanism tests
- `--vendor` and `--vendor-profile` CLI options
- Auto-detection of vendor mechanisms from C_GetMechanismList
- Cross-verification for vendor mechanisms where reference implementations exist

### Phase 2g — Robustness, Performance & Compliance
- `test_access.py`, `test_token.py`, `test_search.py`, `test_mechflags.py`
- `test_fuzz.py` — hypothesis property tests
- `test_resource.py` — memory/leak detection
- `test_stress.py` — concurrency
- `test_benchmark.py` — performance baseline
- `test_rng.py` — RNG quality
- `test_fips.py` — FIPS checks
- `test_protocol.py` — TLS/CMS/JWT
- `test_interop.py` — encoding corpora, malformed inputs
- `--profile` option and named run profiles
- Per-device baseline support

## 22. Test Count Summary

| Category | Count |
|----------|-------|
| Existing (Phase 1) | 85 |
| Cross-verification | ~55 |
| NIST KAT (incl. PQC) | ~60 |
| Wycheproof vectors | ~1,200 |
| Key management | ~25 |
| Multi-part operations | ~20 |
| Access control | ~25 |
| Token management | ~10 |
| Object search | ~10 |
| Error conditions | ~30 |
| Mechanism flags | ~10 |
| v3.0 message-based operations | ~40 |
| v3.2 async operations | ~10 |
| KEM / PQC | ~30 |
| Authenticated wrap/unwrap | ~12 |
| Profile validation | ~10 |
| Session validation flags | ~8 |
| C_LoginUser | ~8 |
| C_SessionCancel | ~8 |
| Interface negotiation edge cases | ~10 |
| API security attacks (all subcategories) | ~70 |
| Padding oracle | ~8 |
| ECDSA nonce quality | ~5 |
| Timing side-channel | ~8 |
| Known CVE regression | ~10 |
| Stateful model testing | ~15 |
| Differential testing | ~20 |
| Metamorphic testing | ~25 |
| Crash / fault injection | ~25 |
| Interoperability / encoding | ~40 |
| Fuzz (hypothesis) | ~20 |
| Memory/resource | ~15 |
| RNG quality | ~5 |
| Benchmark | ~25 |
| Stress/concurrency | ~15 |
| FIPS compliance | ~5 |
| Protocol integration | ~10 |
| Surface audit / hidden probing | ~50 |
| Vendor mechanisms (8 vendors × ~30) | ~240 |
| **Total** | **~2,400+** |

## 23. Future Work Notes

**Cluster and cloud HSM testing (future):** failover during active operations, replica
consistency after key creation, session invalidation across nodes. Requires multi-node
test infrastructure not covered in this spec.

## 24. References

- [Google pkcs11test](https://github.com/google/pkcs11test) — archived Jan 2025, v2.2 coverage
- [Galois Model-Based PKCS#11 Testing](https://galois.com/reports/2020-10-model-based-compliance-testing-of-pkcs11-providers/) — 40,861 auto-generated tests
- [Wycheproof](https://github.com/C2SP/wycheproof) — cryptographic edge-case vectors
- [Bortolozzo et al. "Attacking PKCS#11"](https://lsv.ens-paris-saclay.fr/Publis/PAPERS/PDF/BCFS-ccs10.pdf) — CCS 2010
- [Bardou et al. "Padding Oracle on Hardware"](https://eprint.iacr.org/2012/417.pdf) — CRYPTO 2012
- [Trail of Bits "ECDSA: Handle with Care"](https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/)
- [ROBOT Attack](https://robotattack.org/) — Bleichenbacher on TLS
- [NIST CAVP](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program)
- [NIST SP 800-22](https://csrc.nist.gov/publications/detail/sp/800-22/rev-1a/final) — RNG testing
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA
- [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) — SLH-DSA
- [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final)
- [ROCA CVE-2017-15361](https://crocs.fi.muni.cz/public/papers/rsa_ccs17)
- [PuTTY CVE-2024-31497](https://nvd.nist.gov/vuln/detail/CVE-2024-31497)
- [hypothesis stateful testing](https://hypothesis.readthedocs.io/en/latest/stateful.html)
- [PKCS#11 v3.2 specification](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)
