# p11test Comprehensive Testing Design Specification

**Date:** 2026-03-16
**Status:** Draft
**Depends on:** `2026-03-16-p11test-design.md` (Phase 1 spec)

## 1. Overview

Expand p11test from ~85 basic tests to a comprehensive PKCS#11 test suite covering
cryptographic correctness, security attack vectors, robustness, performance, and
compliance. Target: ~1,600 tests that match or exceed coverage of Google pkcs11test,
Galois model-based testing, and Wycheproof edge-case vectors.

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

Estimated: ~40 tests.

### 2.2 NIST Known-Answer Test Vectors (`test_kat.py`)

Static test vectors from NIST CAVP — import key, compute, compare with known answer.

**Sources:**
- AES: NIST SP 800-38A (ECB, CBC, CTR, OFB, CFB), SP 800-38D (GCM)
- SHA: SHAVS (SHA-1, SHA-224/256/384/512)
- RSA: FIPS 186-4 signature vectors
- ECDSA: FIPS 186-4 P-256, P-384, P-521 vectors
- HMAC: FIPS 198-1 vectors
- AES-KW: RFC 3394 test vectors

**Implementation:** JSON files in `src/p11test/testcases/vectors/` loaded via
`@pytest.mark.parametrize`.

Estimated: ~30 tests.

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
- `valid` → operation must succeed
- `invalid` → operation must fail (or produce different output)
- `acceptable` → either is OK

Estimated: ~1,200 parametrized test cases.

### 2.4 Comprehensive Mechanism Coverage (`test_encrypt.py`, `test_sign.py` expanded)

Extend existing tests to cover every mechanism + parameter combination:

**Symmetric ciphers:**

| Mechanism | Parameters | Key sizes | Tests |
|-----------|-----------|-----------|-------|
| AES-ECB | none | 128, 192, 256 | encrypt/decrypt, KAT |
| AES-CBC | IV (16B) | 128, 192, 256 | encrypt/decrypt, KAT, padding |
| AES-CBC-PAD | IV (16B) | 128, 192, 256 | PKCS7 padding correctness |
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

Estimated: ~10 tests.

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

## 3. Security Testing

### 3.1 PKCS#11 API Security Attacks (`test_api_security.py`)

From Bortolozzo et al. "Attacking and Fixing PKCS#11 Security Tokens" (CCS 2010):

| Attack vector | Test |
|---------------|------|
| Wrap-decrypt oracle | Key with CKA_WRAP + CKA_DECRYPT → wrap under self → decrypt = extract key. Module SHOULD prevent this. |
| Sensitive extraction | CKA_SENSITIVE key → C_GetAttributeValue(CKA_VALUE) → must fail |
| Attribute escalation | Set CKA_EXTRACTABLE=True after creation with False → must fail |
| Key role confusion | Use signing key for encryption |
| Template attack on unwrap | C_UnwrapKey with template overriding CKA_SENSITIVE=False |
| Re-import as wrapping key | Export public key → re-import with CKA_WRAP → attempt wrapping |

Estimated: ~15 tests. These are **security findings** — flagged as warnings, not hard failures
(because some modules intentionally allow certain combinations).

### 3.2 Padding Oracle Detection (`test_padding_oracle.py`)

From Bardou et al. (2012):

| Test | Description |
|------|-------------|
| RSA PKCS#1 v1.5 error uniformity | Decrypt valid vs invalid ciphertext → error code must be identical |
| RSA PKCS#1 v1.5 timing | 1000 valid + 1000 invalid decrypts → timing difference < threshold |
| AES-CBC padding error uniformity | Corrupt last byte vs middle byte → same error code |
| OAEP error uniformity | Invalid OAEP → all errors should be CKR_ENCRYPTED_DATA_INVALID |

Estimated: ~8 tests.

### 3.3 ECDSA Nonce Quality (`test_nonce_quality.py`)

From Trail of Bits "ECDSA: Handle with Care" and PuTTY CVE-2024-31497:

| Test | Description |
|------|-------------|
| Nonce reuse | Sign same message 100× → all `r` values unique (if any repeat → CRITICAL) |
| Nonce bias (upper bits) | 10,000 signatures → statistical test on `r` distribution |
| Deterministic check (RFC 6979) | Sign same message twice → if r,s identical → deterministic (report) |
| P-521 upper-bit bias | Specifically check for PuTTY-style 9-bit bias on P-521 |

Estimated: ~5 tests.

### 3.4 Timing Side-Channel (`test_timing.py`)

| Test | Description |
|------|-------------|
| RSA decrypt timing | Valid vs invalid ciphertext → t-test, N=1000 |
| HMAC verify timing | Correct vs incorrect MAC → t-test |
| Signature verify timing | Valid vs invalid signature → t-test |

Note: Timing tests are **informational** — flagged as warnings with confidence intervals.
Statistical significance threshold: p < 0.001.

Estimated: ~8 tests.

### 3.5 Known CVE Regression (`test_regressions.py`)

| CVE/Bug | Test |
|---------|------|
| ROCA (CVE-2017-15361) | Check RSA public key for Infineon vulnerability fingerprint |
| PuTTY P-521 bias (CVE-2024-31497) | Check for nonce bias in first 9 bits |
| ROBOT attack | RSA PKCS#1 v1.5 error oracle check |

Estimated: ~10 tests.

## 4. Robustness Testing

### 4.1 Fuzz Testing (`test_fuzz.py`)

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

### 4.2 Memory & Resource Safety (`test_resource.py`)

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

### 4.3 RNG Quality (`test_rng.py`)

| Test | Description |
|------|-------------|
| Non-zero | 1KB → not all zeros |
| Non-repeating | 1000 × 32B → all unique |
| Bit frequency | Chi-squared on 100KB |
| Runs test | NIST SP 800-22 basic frequency |
| Monobit test | Frequency of 0s vs 1s within tolerance |

Estimated: ~5 tests.

## 5. Performance Testing

### 5.1 Benchmarks (`test_benchmark.py`)

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

### 5.2 Concurrency & Stress (`test_stress.py`)

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

## 6. Compliance Testing

### 6.1 FIPS 140-3 Checks (`test_fips.py`)

| Test | Description |
|------|-------------|
| Power-on self-test | C_Initialize succeeds (implies self-tests passed) |
| FIPS mode detection | Check CKF_FIPS_APPROVED flag if available |
| Approved algorithms only | In FIPS mode, MD5/DES should be unavailable |
| Zeroization | After C_Finalize, old handles must fail |

Estimated: ~5 tests.

### 6.2 Protocol Integration (`test_protocol.py`)

| Test | Description |
|------|-------------|
| TLS-like signing | Sign ServerKeyExchange structure → verify |
| CMS/PKCS#7 signing | Sign CMS → verify with `cryptography` |
| CSR generation (PKCS#10) | Sign CSR → parse and verify |
| X.509 self-signed cert | Self-sign certificate → verify chain |
| JWT signing | Sign JWT payload → verify with public key |

Estimated: ~10 tests.

## 7. Test File Organization

```
src/p11test/testcases/
├── vectors/                    # Static test vector data
│   ├── nist/                   # NIST CAVP vectors (JSON)
│   │   ├── aes_cbc.json
│   │   ├── aes_gcm.json
│   │   ├── sha256.json
│   │   └── ...
│   ├── wycheproof/             # Wycheproof vectors (JSON, git submodule or vendored)
│   │   ├── aes_gcm_test.json
│   │   ├── ecdsa_secp256r1_sha256_test.json
│   │   └── ...
│   └── rfc/                    # RFC test vectors
│       ├── rfc3394_aes_kw.json
│       └── rfc5649_aes_kwp.json
├── conftest.py                 # Shared fixtures, vector loader
├── test_interface.py           # existing
├── test_slot.py                # existing
├── test_object.py              # existing, expanded
├── test_mechanism.py           # existing, expanded
├── test_encrypt.py             # existing, expanded with all symmetric ciphers
├── test_sign.py                # existing, expanded with all asymmetric sign/verify
├── test_digest.py              # existing, expanded
├── test_errors.py              # existing, expanded (Galois-style)
├── test_crossverify.py         # NEW: cross-verification with `cryptography`
├── test_kat.py                 # NEW: NIST known-answer tests
├── test_wycheproof.py          # NEW: Wycheproof edge-case vectors
├── test_keymgmt.py             # NEW: import, export, wrap, unwrap, derive
├── test_multipart.py           # NEW: multi-part + dual-function
├── test_access.py              # NEW: attribute enforcement, session types
├── test_token.py               # NEW: @destructive — InitToken, PIN mgmt
├── test_search.py              # NEW: object search & enumeration
├── test_mechflags.py           # NEW: mechanism flags validation
├── test_api_security.py        # NEW: Tookan-style attribute attacks
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
└── test_interop.py             # NEW: import/export with cryptography
```

## 8. New Dependencies

```toml
dependencies = [
    # existing...
    "cryptography>=44.0",       # cross-verification, interop
]

[project.optional-dependencies]
dev = [
    # existing...
    "hypothesis>=6.0",          # fuzz testing
    "pytest-benchmark>=4.0",    # benchmarks
]
```

## 9. New Markers

```python
@pytest.mark.crossverify    # tests that verify against cryptography lib
@pytest.mark.kat            # NIST known-answer tests
@pytest.mark.wycheproof     # Wycheproof edge-case vectors
@pytest.mark.security       # security attack vector tests
@pytest.mark.fuzz           # hypothesis fuzzing (slow)
@pytest.mark.benchmark      # performance tests (slow)
@pytest.mark.stress         # resource/concurrency stress (slow)
@pytest.mark.timing         # timing side-channel (slow, informational)
@pytest.mark.destructive    # modifies token state (existing)
@pytest.mark.needs_mechanism("AES_GCM")  # mechanism-specific (existing)
```

## 10. Test Result Classification

Not all failures are equal. Tests should report findings at different severity levels:

| Level | Meaning | Example |
|-------|---------|---------|
| FAIL | Incorrect behavior | AES-CBC decrypts to wrong plaintext |
| SECURITY | Security vulnerability detected | Padding oracle distinguishable errors |
| WARNING | Potentially concerning | Timing difference >2σ but <3σ |
| INFO | Informational finding | Module uses deterministic ECDSA (good) |
| SKIP | Not applicable | Mechanism not supported |

Implementation: Custom pytest plugin hook that annotates test results with severity.

## 11. Phasing

### Phase 2a — Cross-Verification & Mechanism Coverage (first)
- `test_crossverify.py` — ~40 tests
- `test_kat.py` — ~30 tests
- `test_keymgmt.py` — ~25 tests
- `test_multipart.py` — ~20 tests
- Expand existing test files with parameter matrices
- Add `cryptography` dependency

### Phase 2b — Wycheproof Vectors
- `test_wycheproof.py` — ~1,200 parametrized tests
- Vector loader infrastructure
- Wycheproof JSON files (vendored or submodule)

### Phase 2c — Security Testing
- `test_api_security.py` — Tookan-style attacks
- `test_padding_oracle.py` — error oracle detection
- `test_nonce_quality.py` — ECDSA nonce analysis
- `test_timing.py` — timing side-channels
- `test_regressions.py` — known CVE checks

### Phase 2d — Robustness & Performance
- `test_fuzz.py` — hypothesis property tests
- `test_resource.py` — memory/leak detection
- `test_stress.py` — concurrency
- `test_benchmark.py` — performance baseline
- `test_rng.py` — RNG quality

### Phase 2e — Compliance & Integration
- `test_access.py`, `test_token.py`, `test_search.py`, `test_mechflags.py`
- `test_fips.py` — FIPS checks
- `test_protocol.py` — TLS/CMS/JWT
- `test_interop.py` — import/export

## 12. Test Count Summary

| Category | Count |
|----------|-------|
| Existing (Phase 1) | 85 |
| Cross-verification | ~40 |
| NIST KAT | ~30 |
| Wycheproof vectors | ~1,200 |
| Key management | ~25 |
| Multi-part operations | ~20 |
| Access control | ~25 |
| Token management | ~10 |
| Object search | ~10 |
| Error conditions | ~30 |
| Mechanism flags | ~10 |
| API security attacks | ~15 |
| Padding oracle | ~8 |
| ECDSA nonce quality | ~5 |
| Timing side-channel | ~8 |
| Known CVE regression | ~10 |
| Fuzz (hypothesis) | ~20 |
| Memory/resource | ~15 |
| RNG quality | ~5 |
| Benchmark | ~25 |
| Stress/concurrency | ~15 |
| FIPS compliance | ~5 |
| Protocol integration | ~10 |
| Interoperability | ~10 |
| **Total** | **~1,700** |

## 13. References

- [Google pkcs11test](https://github.com/google/pkcs11test) — archived Jan 2025, v2.2 coverage
- [Galois Model-Based PKCS#11 Testing](https://galois.com/reports/2020-10-model-based-compliance-testing-of-pkcs11-providers/) — 40,861 auto-generated tests
- [Wycheproof](https://github.com/C2SP/wycheproof) — cryptographic edge-case vectors
- [Bortolozzo et al. "Attacking PKCS#11"](https://lsv.ens-paris-saclay.fr/Publis/PAPERS/PDF/BCFS-ccs10.pdf) — CCS 2010
- [Bardou et al. "Padding Oracle on Hardware"](https://eprint.iacr.org/2012/417.pdf) — CRYPTO 2012
- [Trail of Bits "ECDSA: Handle with Care"](https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/)
- [ROBOT Attack](https://robotattack.org/) — Bleichenbacher on TLS
- [NIST CAVP](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program)
- [NIST SP 800-22](https://csrc.nist.gov/publications/detail/sp/800-22/rev-1a/final) — RNG testing
- [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final)
- [ROCA CVE-2017-15361](https://crocs.fi.muni.cz/public/papers/rsa_ccs17)
- [PuTTY CVE-2024-31497](https://nvd.nist.gov/vuln/detail/CVE-2024-31497)
